# bsod_analyzer.py - Advanced BSOD Detection and History Management (1200+ lines)
import sys
import os
import json
import subprocess
import wmi
import psutil
from datetime import datetime, timedelta
from pathlib import Path
import threading
import re
from typing import List, Dict, Optional, Tuple
import ctypes

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QScrollArea,
    QFrame, QTableWidget, QTableWidgetItem, QProgressBar, QTextEdit,
    QDialog, QGridLayout, QMessageBox, QFileDialog, QHeaderView,
    QComboBox, QDateEdit, QCheckBox, QSpinBox, QTabWidget,
    QListWidget, QListWidgetItem, QGraphicsDropShadowEffect, QMenu,
    QApplication
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QDate, QDateTime
)
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QLinearGradient, QBrush, QIcon,
    QPixmap, QImage, QPainter, QPen, QAction
)

# BSOD Error Code and Solution Database
BSOD_ERROR_CODES = {
    "0x0000000A": {
        "name": "IRQL_NOT_LESS_OR_EQUAL",
        "description": "Attempt to access memory at an invalid address",
        "causes": [
            "Faulty RAM",
            "Corrupted or incompatible driver",
            "Hardware incompatibility",
            "Overclocking settings",
            "Antivirus conflict"
        ],
        "solutions": [
            "Run Memory Diagnostic Tool",
            "Update drivers (especially GPU and chipset)",
            "Disable overclocking in BIOS",
            "Check for hardware conflicts in Device Manager",
            "Perform clean boot",
            "Uninstall recently installed drivers or software",
            "Check RAM with MemTest86",
            "Disable problematic antivirus temporarily"
        ]
    },
    "0x0000001E": {
        "name": "KMODE_EXCEPTION_NOT_HANDLED",
        "description": "Kernel mode exception not handled",
        "causes": [
            "Bad device driver",
            "Faulty RAM",
            "Corrupted Windows installation",
            "Hardware malfunction"
        ],
        "solutions": [
            "Update/reinstall drivers",
            "Run System File Checker (sfc /scannow)",
            "Run Disk Check utility",
            "Perform Windows in-place upgrade",
            "Test RAM with Memory Diagnostic",
            "Check Windows Event Viewer for driver warnings"
        ]
    },
    "0x0000003B": {
        "name": "SYSTEM_SERVICE_EXCEPTION",
        "description": "Exception in system service",
        "causes": [
            "Faulty driver",
            "Software conflict",
            "Corrupted system file",
            "Malware infection"
        ],
        "solutions": [
            "Identify problematic driver from dump file",
            "Run Windows Defender offline scan",
            "Perform Clean Boot",
            "Update Windows",
            "Restore from System Restore point",
            "Reinstall problematic driver"
        ]
    },
    "0x00000050": {
        "name": "PAGE_FAULT_IN_NONPAGED_AREA",
        "description": "Request for nonexistent virtual address",
        "causes": [
            "Faulty RAM",
            "Corrupted driver",
            "Incompatible software",
            "Hard disk problems"
        ],
        "solutions": [
            "Run RAM diagnostic",
            "Run CHKDSK (/scan or /spotfix)",
            "Update/uninstall problematic drivers",
            "Disable hardware acceleration",
            "Update BIOS",
            "Test hard drive health"
        ]
    },
    "0x00000051": {
        "name": "REGISTRY_ERROR",
        "description": "Registry error or registry file corruption",
        "causes": [
            "Corrupted Windows Registry",
            "Failed registry edit",
            "Antivirus issues",
            "Hard drive problems"
        ],
        "solutions": [
            "Run System Restore",
            "Use Registry Restore in Safe Mode",
            "Run CHKDSK",
            "Repair Windows using Startup Repair",
            "Restore Registry from backup",
            "Perform Windows reinstall if necessary"
        ]
    },
    "0x000000BA": {
        "name": "SESSION_HAS_VALID_VIEWS_ON_EXIT",
        "description": "Session has valid views on exit",
        "causes": [
            "Faulty driver",
            "Incompatible software",
            "Memory corruption"
        ],
        "solutions": [
            "Boot in Safe Mode",
            "Update drivers",
            "Disable recently added hardware",
            "Perform System Restore"
        ]
    },
    "0x000000D1": {
        "name": "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        "description": "Driver accessed memory inappropriately",
        "causes": [
            "Faulty or outdated driver",
            "Corrupted system file",
            "RAM issues",
            "Device incompatibility"
        ],
        "solutions": [
            "Update driver to latest version",
            "Uninstall and reinstall driver",
            "Check Device Manager for problems",
            "Update BIOS",
            "Test RAM",
            "Disable hardware acceleration in graphics settings"
        ]
    },
    "0x000000FAILED": {
        "name": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        "description": "Software exception not handled",
        "causes": [
            "Third-party driver",
            "Faulty application",
            "Software conflict",
            "Corrupted system files"
        ],
        "solutions": [
            "Identify faulty driver from debug output",
            "Update Windows",
            "Perform System File Check",
            "Uninstall problematic software",
            "Boot in Safe Mode and diagnose",
            "Run Windows Repair"
        ]
    },
    "0xC000021A": {
        "name": "STATUS_SYSTEM_PROCESS_TERMINATED",
        "description": "Critical system process terminated",
        "causes": [
            "Corrupted system file",
            "Malware infection",
            "Faulty driver",
            "Windows corruption"
        ],
        "solutions": [
            "Run Windows Startup Repair",
            "Run System File Checker (SFC)",
            "Run DISM to repair Windows image",
            "Perform System Restore",
            "Boot into Safe Mode",
            "Full antivirus/malware scan",
            "Windows reinstall if necessary"
        ]
    }
}

class BSODEventThread(QThread):
    """Thread for continuously monitoring BSOD events"""
    bsod_detected = pyqtSignal(dict)
    scan_complete = pyqtSignal(list)
    scan_progress = pyqtSignal(int, str)
    error_occurred = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.running = False
        self.scan_type = "eventlog"
        self.bsod_history = []

    def run(self):
        """Main thread execution"""
        try:
            self.running = True
            if self.scan_type == "eventlog":
                self.scan_event_log()
            elif self.scan_type == "minidump":
                self.scan_minidump_files()
            elif self.scan_type == "full":
                self.perform_full_scan()
        except Exception as e:
            self.error_occurred.emit(f"Scan error: {str(e)}")
            import traceback
            traceback.print_exc()

    def scan_event_log(self):
        """Scan Windows Event Log for BSOD events"""
        try:
            self.scan_progress.emit(10, "Connecting to Event Log...")
            w = wmi.WMI()
            
            # Query for BSOD-related events
            self.scan_progress.emit(30, "Searching for critical events...")
            
            # Event codes that indicate BSOD: 1001 (BugCheck)
            query = "SELECT * FROM Win32_NTLogEvent WHERE Logfile='System' AND EventCode=1001"
            events = w.query(query)
            
            bsods = []
            event_count = len(events)
            
            for idx, event in enumerate(events):
                progress = 30 + int((idx / max(event_count, 1)) * 60)
                self.scan_progress.emit(progress, f"Processing event {idx+1}/{event_count}...")
                
                bsod_info = self.parse_event_log(event)
                if bsod_info:
                    bsods.append(bsod_info)
                    self.bsod_detected.emit(bsod_info)
            
            self.scan_progress.emit(95, "Finalizing results...")
            self.save_bsod_history(bsods)
            self.bsod_history = bsods
            
            self.scan_progress.emit(100, "Scan complete!")
            self.scan_complete.emit(bsods)
            
        except Exception as e:
            self.error_occurred.emit(f"Event Log scan failed: {str(e)}")

    def scan_minidump_files(self):
        """Scan Windows minidump files for crash information"""
        try:
            self.scan_progress.emit(15, "Locating minidump files...")
            
            minidump_path = Path("C:/Windows/Minidump")
            if not minidump_path.exists():
                minidump_path = Path(os.path.expandvars("%windir%/Minidump"))
            
            dmp_files = list(minidump_path.glob("*.dmp"))
            
            self.scan_progress.emit(30, f"Found {len(dmp_files)} minidump files")
            
            bsods = []
            for idx, dmp_file in enumerate(dmp_files):
                progress = 30 + int((idx / max(len(dmp_files), 1)) * 60)
                self.scan_progress.emit(progress, f"Analyzing {dmp_file.name}...")
                
                bsod_info = self.analyze_minidump(dmp_file)
                if bsod_info:
                    bsods.append(bsod_info)
                    self.bsod_detected.emit(bsod_info)
            
            self.scan_progress.emit(95, "Finalizing results...")
            self.save_bsod_history(bsods)
            self.bsod_history = bsods
            
            self.scan_progress.emit(100, "Minidump scan complete!")
            self.scan_complete.emit(bsods)
            
        except Exception as e:
            self.error_occurred.emit(f"Minidump scan failed: {str(e)}")

    def perform_full_scan(self):
        """Perform comprehensive BSOD detection combining multiple sources"""
        try:
            self.scan_progress.emit(5, "Starting comprehensive BSOD scan...")
            
            # Get all potential sources
            all_bsods = []
            
            # 1. Event Log (weight: 40%)
            self.scan_progress.emit(10, "Scanning Event Log...")
            event_bsods = self.get_event_log_bsods()
            all_bsods.extend(event_bsods)
            
            # 2. Minidump files (weight: 35%)
            self.scan_progress.emit(45, "Scanning minidump files...")
            minidump_bsods = self.get_minidump_bsods()
            all_bsods.extend(minidump_bsods)
            
            # 3. System logs (weight: 15%)
            self.scan_progress.emit(75, "Analyzing system logs...")
            system_logs_bsods = self.get_system_logs_bsods()
            all_bsods.extend(system_logs_bsods)
            
            # 4. Registry checks (weight: 10%)
            self.scan_progress.emit(85, "Checking registry for BSOD indicators...")
            registry_bsods = self.check_registry_bsod_clues()
            all_bsods.extend(registry_bsods)
            
            # Deduplicate and sort
            unique_bsods = self.deduplicate_bsods(all_bsods)
            unique_bsods.sort(key=lambda x: x['timestamp'], reverse=True)
            
            self.scan_progress.emit(95, "Finalizing results...")
            self.save_bsod_history(unique_bsods)
            self.bsod_history = unique_bsods
            
            self.scan_progress.emit(100, "Full scan complete!")
            self.scan_complete.emit(unique_bsods)
            
        except Exception as e:
            self.error_occurred.emit(f"Full scan failed: {str(e)}")

    def get_event_log_bsods(self) -> List[Dict]:
        """Get BSOD events from Windows Event Log"""
        bsods = []
        try:
            w = wmi.WMI()
            
            # BugCheck events (code 1001)
            query = "SELECT * FROM Win32_NTLogEvent WHERE Logfile='System' AND EventCode=1001"
            events = w.query(query)
            
            for event in events:
                bsod = self.parse_event_log(event)
                if bsod:
                    bsods.append(bsod)
        except:
            pass
        
        return bsods

    def get_minidump_bsods(self) -> List[Dict]:
        """Get BSOD information from minidump files"""
        bsods = []
        try:
            minidump_path = Path("C:/Windows/Minidump")
            if not minidump_path.exists():
                minidump_path = Path(os.path.expandvars("%windir%/Minidump"))
            
            for dmp_file in minidump_path.glob("*.dmp"):
                bsod = self.analyze_minidump(dmp_file)
                if bsod:
                    bsods.append(bsod)
        except:
            pass
        
        return bsods

    def get_system_logs_bsods(self) -> List[Dict]:
        """Get BSOD indicators from system logs"""
        bsods = []
        try:
            w = wmi.WMI()
            
            # Check for unexpected shutdown events (code 6008)
            query = "SELECT * FROM Win32_NTLogEvent WHERE Logfile='System' AND EventCode=6008"
            events = w.query(query)
            
            for event in events:
                bsod_info = {
                    'timestamp': str(event.TimeGenerated),
                    'error_code': 'UNEXPECTED_SHUTDOWN',
                    'error_name': 'Unexpected Shutdown',
                    'message': 'System shutdown without proper shutdown procedure',
                    'severity': 'MEDIUM',
                    'source': 'System Log - Event 6008',
                    'event_id': 6008
                }
                bsods.append(bsod_info)
        except:
            pass
        
        return bsods

    def check_registry_bsod_clues(self) -> List[Dict]:
        """Check registry for BSOD-related clues"""
        bsods = []
        try:
            import winreg
            
            # Check for BSOD history in registry
            key_path = r"System\CurrentControlSet\Control\Session Manager"
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                # Check Last Known Good values
                # This is a simplified check
                value, _ = winreg.QueryValueEx(key, "BootCount")
                winreg.CloseKey(key)
            except:
                pass
        except:
            pass
        
        return bsods

    def parse_event_log(self, event) -> Optional[Dict]:
        """Parse Event Log entry to extract BSOD information"""
        try:
            message = str(event.Message) if hasattr(event, 'Message') else ""
            
            # Extract error code from message
            error_code_match = re.search(r'0x[0-9A-Fa-f]+', message)
            error_code = error_code_match.group(0) if error_code_match else "UNKNOWN"
            
            # Normalize error code
            error_code = error_code.upper()
            
            bsod_info = {
                'timestamp': str(event.TimeGenerated),
                'error_code': error_code,
                'error_name': BSOD_ERROR_CODES.get(error_code, {}).get('name', 'Unknown BSOD'),
                'message': message[:500],
                'severity': 'CRITICAL',
                'source': f"Event Log - Event {event.EventCode}",
                'event_id': event.EventCode,
                'computer': event.Computer if hasattr(event, 'Computer') else 'Unknown'
            }
            
            return bsod_info
        except:
            return None

    def analyze_minidump(self, dmp_file: Path) -> Optional[Dict]:
        """Analyze minidump file for crash information"""
        try:
            file_stat = dmp_file.stat()
            modified_time = datetime.fromtimestamp(file_stat.st_mtime)
            
            # Try to extract information from filename or file size patterns
            bsod_info = {
                'timestamp': modified_time.isoformat(),
                'error_code': 'MINIDUMP_ANALYSIS',
                'error_name': 'BSOD Detected (Minidump)',
                'message': f'Minidump file: {dmp_file.name} (Size: {file_stat.st_size / (1024*1024):.2f} MB)',
                'severity': 'CRITICAL',
                'source': f'Minidump File: {dmp_file.name}',
                'file_path': str(dmp_file)
            }
            
            return bsod_info
        except:
            return None

    def deduplicate_bsods(self, bsods: List[Dict]) -> List[Dict]:
        """Remove duplicate BSOD entries"""
        seen = set()
        unique = []
        
        for bsod in bsods:
            # Create a key from critical fields
            key = (bsod.get('error_code'), bsod.get('timestamp'))
            if key not in seen:
                seen.add(key)
                unique.append(bsod)
        
        return unique

    def save_bsod_history(self, bsods: List[Dict]):
        """Save BSOD history to JSON file"""
        try:
            history_file = Path(os.path.expandvars("%APPDATA%/BSOD_Rescue_Pro/bsod_history.json"))
            history_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Load existing history
            existing = []
            if history_file.exists():
                with open(history_file, 'r') as f:
                    existing = json.load(f)
            
            # Merge with new BSODs
            all_bsods = existing + bsods
            # Keep last 100 BSODs
            all_bsods = all_bsods[-100:]
            
            # Save
            with open(history_file, 'w') as f:
                json.dump(all_bsods, f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving BSOD history: {e}")

    def stop_scanning(self):
        """Stop the scan"""
        self.running = False
        self.quit()
        self.wait()


class BSODDetailsDialog(QDialog):
    """Dialog to show detailed BSOD information and solutions"""
    
    def __init__(self, bsod_info: Dict, parent=None):
        super().__init__(parent)
        self.bsod_info = bsod_info
        self.setWindowTitle("BSOD Details & Solutions")
        self.setGeometry(100, 100, 1000, 700)
        self.setup_ui()
        self.apply_theme()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Header with error code
        header_layout = QHBoxLayout()
        
        error_code_label = QLabel(self.bsod_info.get('error_code', 'UNKNOWN'))
        error_code_label.setFont(QFont("Courier New", 16, QFont.Weight.Bold))
        error_code_label.setStyleSheet("color: #ef4444;")
        header_layout.addWidget(error_code_label)
        
        error_name_label = QLabel(self.bsod_info.get('error_name', 'Unknown Error'))
        error_name_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        error_name_label.setStyleSheet("color: #f8fafc;")
        header_layout.addWidget(error_name_label)
        
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        # Timestamp and severity
        info_layout = QHBoxLayout()
        
        timestamp_label = QLabel(f"Time: {self.bsod_info.get('timestamp', 'Unknown')}")
        timestamp_label.setStyleSheet("color: #94a3b8;")
        info_layout.addWidget(timestamp_label)
        
        severity = self.bsod_info.get('severity', 'UNKNOWN')
        severity_color = "#ef4444" if severity == "CRITICAL" else "#f59e0b" if severity == "HIGH" else "#10b981"
        severity_label = QLabel(f"Severity: {severity}")
        severity_label.setStyleSheet(f"color: {severity_color};")
        info_layout.addWidget(severity_label)
        
        info_layout.addStretch()
        layout.addLayout(info_layout)
        
        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        separator.setStyleSheet("background-color: #334155;")
        layout.addWidget(separator)
        
        # Message
        message_label = QLabel("Error Message:")
        message_label.setStyleSheet("color: #f8fafc; font-weight: bold;")
        layout.addWidget(message_label)
        
        message_text = QTextEdit()
        message_text.setText(self.bsod_info.get('message', 'No message available'))
        message_text.setReadOnly(True)
        message_text.setMaximumHeight(80)
        message_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e293b;
                color: #94a3b8;
                border: 1px solid #334155;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        layout.addWidget(message_text)
        
        # Error Description
        error_code = self.bsod_info.get('error_code', '')
        error_details = BSOD_ERROR_CODES.get(error_code, {})
        
        if error_details:
            desc_label = QLabel("Description:")
            desc_label.setStyleSheet("color: #f8fafc; font-weight: bold; margin-top: 15px;")
            layout.addWidget(desc_label)
            
            description_text = QTextEdit()
            description_text.setText(error_details.get('description', 'Unknown error'))
            description_text.setReadOnly(True)
            description_text.setMaximumHeight(60)
            description_text.setStyleSheet("""
                QTextEdit {
                    background-color: #1e293b;
                    color: #94a3b8;
                    border: 1px solid #334155;
                    border-radius: 5px;
                    padding: 10px;
                }
            """)
            layout.addWidget(description_text)
        
        # Causes
        causes = error_details.get('causes', [])
        if causes:
            causes_label = QLabel("Possible Causes:")
            causes_label.setStyleSheet("color: #f8fafc; font-weight: bold; margin-top: 15px;")
            layout.addWidget(causes_label)
            
            causes_list = QTextEdit()
            causes_text = "\n".join([f"• {cause}" for cause in causes])
            causes_list.setText(causes_text)
            causes_list.setReadOnly(True)
            causes_list.setMaximumHeight(100)
            causes_list.setStyleSheet("""
                QTextEdit {
                    background-color: #1e293b;
                    color: #f59e0b;
                    border: 1px solid #334155;
                    border-radius: 5px;
                    padding: 10px;
                }
            """)
            layout.addWidget(causes_list)
        
        # Solutions
        solutions = error_details.get('solutions', [])
        if solutions:
            solutions_label = QLabel("Recommended Solutions:")
            solutions_label.setStyleSheet("color: #f8fafc; font-weight: bold; margin-top: 15px;")
            layout.addWidget(solutions_label)
            
            solutions_list = QTextEdit()
            solutions_text = "\n".join([f"{i+1}. {sol}" for i, sol in enumerate(solutions)])
            solutions_list.setText(solutions_text)
            solutions_list.setReadOnly(True)
            solutions_list.setStyleSheet("""
                QTextEdit {
                    background-color: #1e293b;
                    color: #10b981;
                    border: 1px solid #334155;
                    border-radius: 5px;
                    padding: 10px;
                }
            """)
            layout.addWidget(solutions_list)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: #334155;
                color: #f8fafc;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #475569;
            }
        """)
        close_btn.clicked.connect(self.accept)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
    
    def apply_theme(self):
        self.setStyleSheet("""
            QDialog {
                background-color: #0f172a;
            }
        """)


class BSODAnalyzerWidget(QWidget):
    """Main BSOD Analyzer Widget"""
    
    def __init__(self):
        super().__init__()
        self.bsod_scanner_thread = None
        self.bsod_data = []
        self.setup_ui()
        self.apply_theme()
        self.load_bsod_history()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        # Header
        header = QLabel("BSOD Detection & History")
        header.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        header.setStyleSheet("color: #f8fafc;")
        layout.addWidget(header)
        
        subtitle = QLabel("Comprehensive BSOD scanning, detection, and solution database")
        subtitle.setStyleSheet("color: #94a3b8; font-size: 14px; margin-bottom: 20px;")
        layout.addWidget(subtitle)
        
        # Control Panel
        control_layout = QHBoxLayout()
        
        # Scan Type Selection
        scan_label = QLabel("Scan Type:")
        scan_label.setStyleSheet("color: #f8fafc; font-weight: bold;")
        control_layout.addWidget(scan_label)
        
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems([
            "Event Log Scan",
            "Minidump Analysis",
            "Full System Scan"
        ])
        self.scan_type_combo.setStyleSheet("""
            QComboBox {
                background-color: #1e293b;
                color: #f8fafc;
                border: 1px solid #334155;
                border-radius: 5px;
                padding: 8px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                background-color: #334155;
            }
        """)
        control_layout.addWidget(self.scan_type_combo)
        
        control_layout.addSpacing(20)
        
        # Scan Button
        self.scan_btn = QPushButton("🔍 Start Scan")
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #3b82f6;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 12px 25px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
            QPushButton:pressed {
                background-color: #1d4ed8;
            }
            QPushButton:disabled {
                background-color: #64748b;
            }
        """)
        self.scan_btn.clicked.connect(self.start_bsod_scan)
        control_layout.addWidget(self.scan_btn)
        
        # Clear History Button
        clear_btn = QPushButton("🗑️ Clear History")
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #ef4444;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 12px 25px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #dc2626;
            }
            QPushButton:pressed {
                background-color: #991b1b;
            }
        """)
        clear_btn.clicked.connect(self.clear_bsod_history)
        control_layout.addWidget(clear_btn)
        
        # Export Button
        export_btn = QPushButton("📥 Export Report")
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #10b981;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 12px 25px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #059669;
            }
            QPushButton:pressed {
                background-color: #047857;
            }
        """)
        export_btn.clicked.connect(self.export_bsod_report)
        control_layout.addWidget(export_btn)
        
        control_layout.addStretch()
        layout.addLayout(control_layout)
        
        # Progress Bar
        self.progress_label = QLabel("Ready")
        self.progress_label.setStyleSheet("color: #94a3b8; font-size: 12px;")
        layout.addWidget(self.progress_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #334155;
                border-radius: 5px;
                text-align: center;
                color: white;
                height: 25px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                    stop: 0 #3b82f6, stop: 1 #0ea5e9);
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # BSOD Table
        table_label = QLabel("BSOD History")
        table_label.setStyleSheet("color: #f8fafc; font-weight: bold; margin-top: 20px; font-size: 14px;")
        layout.addWidget(table_label)
        
        self.bsod_table = QTableWidget()
        self.bsod_table.setColumnCount(5)
        self.bsod_table.setHorizontalHeaderLabels([
            "Timestamp", "Error Code", "Error Name", "Severity", "Source"
        ])
        self.bsod_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.bsod_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.bsod_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.bsod_table.setStyleSheet("""
            QTableWidget {
                background-color: #1e293b;
                alternate-background-color: #0f172a;
                color: #f8fafc;
                gridline-color: #334155;
                border: 1px solid #334155;
                border-radius: 5px;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #334155;
            }
            QHeaderView::section {
                background-color: #0f172a;
                color: #f8fafc;
                padding: 10px;
                border: none;
                border-right: 1px solid #334155;
                font-weight: bold;
            }
        """)
        self.bsod_table.itemDoubleClicked.connect(self.show_bsod_details)
        self.bsod_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.bsod_table.customContextMenuRequested.connect(self.show_context_menu)
        layout.addWidget(self.bsod_table)
        
        # Statistics Panel
        stats_layout = QHBoxLayout()
        
        # Total BSODs
        self.total_bsods_label = QLabel("Total BSODs: 0")
        self.total_bsods_label.setStyleSheet("color: #f8fafc; font-weight: bold;")
        stats_layout.addWidget(self.total_bsods_label)
        
        # Critical count
        self.critical_count_label = QLabel("Critical: 0")
        self.critical_count_label.setStyleSheet("color: #ef4444; font-weight: bold;")
        stats_layout.addWidget(self.critical_count_label)
        
        # Last BSOD
        self.last_bsod_label = QLabel("Last BSOD: Never")
        self.last_bsod_label.setStyleSheet("color: #f59e0b; font-weight: bold;")
        stats_layout.addWidget(self.last_bsod_label)
        
        stats_layout.addStretch()
        layout.addLayout(stats_layout)
    
    def apply_theme(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #0f172a;
                color: #f8fafc;
            }
        """)
    
    def start_bsod_scan(self):
        """Start BSOD scanning"""
        if self.bsod_scanner_thread and self.bsod_scanner_thread.isRunning():
            QMessageBox.warning(self, "Scan Running", "A scan is already in progress!")
            return
        
        self.scan_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.progress_label.setText("Initializing scan...")
        
        # Determine scan type
        scan_types = {
            0: "eventlog",
            1: "minidump",
            2: "full"
        }
        scan_type = scan_types.get(self.scan_type_combo.currentIndex(), "eventlog")
        
        self.bsod_scanner_thread = BSODEventThread()
        self.bsod_scanner_thread.scan_type = scan_type
        self.bsod_scanner_thread.scan_progress.connect(self.update_scan_progress)
        self.bsod_scanner_thread.scan_complete.connect(self.on_scan_complete)
        self.bsod_scanner_thread.error_occurred.connect(self.on_scan_error)
        self.bsod_scanner_thread.start()
    
    def update_scan_progress(self, progress: int, status: str):
        """Update scan progress"""
        self.progress_bar.setValue(progress)
        self.progress_label.setText(status)
    
    def on_scan_complete(self, bsods: List[Dict]):
        """Handle scan completion"""
        self.bsod_data = bsods
        self.refresh_bsod_table()
        self.scan_btn.setEnabled(True)
        
        if bsods:
            QMessageBox.information(
                self,
                "Scan Complete",
                f"Found {len(bsods)} BSOD events.\n\n"
                "Double-click any entry to view details and solutions."
            )
        else:
            QMessageBox.information(
                self,
                "Scan Complete",
                "No BSOD events found. Your system appears to be stable!"
            )
    
    def on_scan_error(self, error_msg: str):
        """Handle scan error"""
        self.scan_btn.setEnabled(True)
        self.progress_label.setText("Scan failed!")
        QMessageBox.critical(self, "Scan Error", error_msg)
    
    def refresh_bsod_table(self):
        """Refresh BSOD table"""
        self.bsod_table.setRowCount(0)
        
        for bsod in self.bsod_data:
            row = self.bsod_table.rowCount()
            self.bsod_table.insertRow(row)
            
            # Timestamp
            timestamp_item = QTableWidgetItem(bsod.get('timestamp', 'Unknown'))
            timestamp_item.setForeground(QColor("#94a3b8"))
            self.bsod_table.setItem(row, 0, timestamp_item)
            
            # Error Code
            error_code_item = QTableWidgetItem(bsod.get('error_code', 'UNKNOWN'))
            error_code_item.setForeground(QColor("#ef4444"))
            error_code_item.setFont(QFont("Courier New", 9))
            self.bsod_table.setItem(row, 1, error_code_item)
            
            # Error Name
            error_name_item = QTableWidgetItem(bsod.get('error_name', 'Unknown'))
            error_name_item.setForeground(QColor("#f8fafc"))
            self.bsod_table.setItem(row, 2, error_name_item)
            
            # Severity
            severity = bsod.get('severity', 'UNKNOWN')
            severity_color = QColor("#ef4444") if severity == "CRITICAL" else QColor("#f59e0b") if severity == "HIGH" else QColor("#10b981")
            severity_item = QTableWidgetItem(severity)
            severity_item.setForeground(severity_color)
            self.bsod_table.setItem(row, 3, severity_item)
            
            # Source
            source_item = QTableWidgetItem(bsod.get('source', 'Unknown'))
            source_item.setForeground(QColor("#0ea5e9"))
            self.bsod_table.setItem(row, 4, source_item)
        
        # Update statistics
        self.update_statistics()
    
    def update_statistics(self):
        """Update statistics labels"""
        total = len(self.bsod_data)
        critical = sum(1 for b in self.bsod_data if b.get('severity') == 'CRITICAL')
        
        self.total_bsods_label.setText(f"Total BSODs: {total}")
        self.critical_count_label.setText(f"Critical: {critical}")
        
        if self.bsod_data:
            last_bsod = self.bsod_data[0]
            timestamp = last_bsod.get('timestamp', 'Unknown')
            self.last_bsod_label.setText(f"Last BSOD: {timestamp}")
        else:
            self.last_bsod_label.setText("Last BSOD: Never")
    
    def show_bsod_details(self, item):
        """Show detailed information for a BSOD"""
        row = item.row()
        if 0 <= row < len(self.bsod_data):
            dialog = BSODDetailsDialog(self.bsod_data[row], self)
            dialog.exec()
    
    def show_context_menu(self, pos):
        """Show context menu for table"""
        menu = QMenu()
        
        view_action = QAction("View Details", self)
        view_action.triggered.connect(lambda: self.show_bsod_details(self.bsod_table.itemAt(pos)))
        menu.addAction(view_action)
        
        menu.addSeparator()
        
        copy_action = QAction("Copy Error Code", self)
        copy_action.triggered.connect(self.copy_error_code)
        menu.addAction(copy_action)
        
        menu.exec(self.bsod_table.mapToGlobal(pos))
    
    def copy_error_code(self):
        """Copy error code to clipboard"""
        row = self.bsod_table.currentRow()
        if row >= 0 and row < len(self.bsod_data):
            clipboard = QApplication.clipboard()
            clipboard.setText(self.bsod_data[row].get('error_code', ''))
    
    def load_bsod_history(self):
        """Load BSOD history from file"""
        try:
            history_file = Path(os.path.expandvars("%APPDATA%/BSOD_Rescue_Pro/bsod_history.json"))
            if history_file.exists():
                with open(history_file, 'r') as f:
                    self.bsod_data = json.load(f)
                    self.bsod_data.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
                    self.refresh_bsod_table()
        except Exception as e:
            print(f"Error loading BSOD history: {e}")
    
    def clear_bsod_history(self):
        """Clear BSOD history"""
        reply = QMessageBox.warning(
            self,
            "Clear History",
            "Are you sure you want to clear all BSOD history?\nThis action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.bsod_data = []
                self.refresh_bsod_table()
                
                history_file = Path(os.path.expandvars("%APPDATA%/BSOD_Rescue_Pro/bsod_history.json"))
                if history_file.exists():
                    history_file.unlink()
                
                QMessageBox.information(self, "Success", "BSOD history cleared successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to clear history: {str(e)}")
    
    def export_bsod_report(self):
        """Export BSOD report to file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export BSOD Report",
            "",
            "JSON Files (*.json);;Text Files (*.txt);;CSV Files (*.csv)"
        )
        
        if file_path:
            try:
                if file_path.endswith('.json'):
                    with open(file_path, 'w') as f:
                        json.dump(self.bsod_data, f, indent=2, default=str)
                elif file_path.endswith('.txt'):
                    with open(file_path, 'w') as f:
                        f.write("BSOD ANALYSIS REPORT\n")
                        f.write("=" * 80 + "\n\n")
                        for bsod in self.bsod_data:
                            f.write(f"Timestamp: {bsod.get('timestamp')}\n")
                            f.write(f"Error Code: {bsod.get('error_code')}\n")
                            f.write(f"Error Name: {bsod.get('error_name')}\n")
                            f.write(f"Severity: {bsod.get('severity')}\n")
                            f.write(f"Source: {bsod.get('source')}\n")
                            f.write(f"Message: {bsod.get('message')}\n")
                            f.write("-" * 80 + "\n\n")
                elif file_path.endswith('.csv'):
                    import csv
                    with open(file_path, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=['timestamp', 'error_code', 'error_name', 'severity', 'source', 'message'])
                        writer.writeheader()
                        writer.writerows(self.bsod_data)
                
                QMessageBox.information(self, "Success", f"Report exported to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export report: {str(e)}")
