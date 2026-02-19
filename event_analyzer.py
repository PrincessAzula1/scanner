# event_analyzer.py - Comprehensive Event Log & BSOD Analyzer (Under 5000 lines)
import sys
import os
import subprocess
import re
import json
import glob
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path
import ctypes
import tempfile
import sqlite3
import hashlib
import base64
from collections import defaultdict

# PyQt6 imports
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem, QProgressBar,
    QTextEdit, QGroupBox, QHeaderView, QMessageBox, QFileDialog,
    QTabWidget, QSplitter, QFrame, QComboBox, QCheckBox, QSpinBox,
    QDateTimeEdit, QDialog, QGridLayout, QRadioButton, QButtonGroup,
    QScrollArea, QStatusBar, QToolBar, QMenu, QMenuBar, QTreeWidget,
    QTreeWidgetItem, QLineEdit, QStackedWidget, QWizard, QWizardPage,
    QListWidget, QListWidgetItem, QProgressDialog, QInputDialog
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QObject, QTimer, QSettings,
    QMimeData, QUrl, QSize, QDateTime, QSortFilterProxyModel,
    QAbstractTableModel, QModelIndex
)
from PyQt6.QtGui import (
    QFont, QColor, QIcon, QPalette, QLinearGradient, QBrush,
    QPainter, QPen, QAction, QKeySequence, QClipboard, QTextCursor,
    QTextCharFormat, QSyntaxHighlighter
)

# Windows-specific imports
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import win32api
    import win32file
    import wmi
    WINDOWS_MODE = True
except ImportError:
    WINDOWS_MODE = False
    print("Warning: Windows-specific features unavailable")

APP_NAME = "Event Analyzer Pro"
APP_VERSION = "3.0"
MAX_LINES = 5000

# Known BSOD error codes with descriptions
BSOD_CODES = {
    "0x00000001": ("APC_INDEX_MISMATCH", "Kernel-mode APC occurred at incorrect IRQL"),
    "0x0000000A": ("IRQL_NOT_LESS_OR_EQUAL", "Driver accessed memory at incorrect IRQL"),
    "0x0000001E": ("KMODE_EXCEPTION_NOT_HANDLED", "Kernel-mode exception not handled"),
    "0x00000024": ("NTFS_FILE_SYSTEM", "NTFS file system corruption"),
    "0x0000002E": ("DATA_BUS_ERROR", "Memory parity error or faulty RAM"),
    "0x0000003B": ("SYSTEM_SERVICE_EXCEPTION", "System service threw exception"),
    "0x00000050": ("PAGE_FAULT_IN_NONPAGED_AREA", "Invalid memory reference"),
    "0x0000007A": ("KERNEL_DATA_INPAGE_ERROR", "Unable to read kernel data from page file"),
    "0x0000007B": ("INACCESSIBLE_BOOT_DEVICE", "Boot device inaccessible"),
    "0x0000007E": ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "System thread exception"),
    "0x0000007F": ("UNEXPECTED_KERNEL_MODE_TRAP", "CPU trap not handled"),
    "0x0000009F": ("DRIVER_POWER_STATE_FAILURE", "Driver power state mismatch"),
    "0x000000A5": ("ACPI_BIOS_ERROR", "ACPI BIOS incompatibility"),
    "0x000000C2": ("BAD_POOL_CALLER", "Invalid pool request"),
    "0x000000C4": ("DRIVER_VERIFIER_DETECTED_VIOLATION", "Driver verifier violation"),
    "0x000000C5": ("DRIVER_CORRUPTED_EXPOOL", "Driver corrupted pool memory"),
    "0x000000D1": ("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "Driver IRQL issue"),
    "0x000000EA": ("THREAD_STUCK_IN_DEVICE_DRIVER", "Device driver stuck in loop"),
    "0x000000EF": ("CRITICAL_PROCESS_DIED", "Critical process terminated"),
    "0x000000F4": ("CRITICAL_OBJECT_TERMINATION", "Critical object termination"),
    "0x00000109": ("CRITICAL_STRUCTURE_CORRUPTION", "Kernel structure corruption"),
    "0x0000010E": ("VIDEO_MEMORY_MANAGEMENT_INTERNAL", "GPU memory management error"),
    "0x00000116": ("VIDEO_TDR_ERROR", "GPU timeout detection recovery"),
    "0x00000117": ("VIDEO_TDR_TIMEOUT_DETECTED", "GPU TDR timeout"),
    "0x00000124": ("WHEA_UNCORRECTABLE_ERROR", "Hardware error (CPU/GPU/RAM)"),
    "0x00000133": ("DPC_WATCHDOG_VIOLATION", "DPC watchdog timeout"),
    "0x00000139": ("KERNEL_SECURITY_CHECK_FAILURE", "Kernel security check failed"),
    "0x00000141": ("VIDEO_ENGINE_TIMEOUT_DETECTED", "Video engine timeout"),
    "0x00000142": ("VIDEO_TDR_APPLICATION_BLOCKED", "Application blocked GPU"),
    "0x00000143": ("PROCESSOR_DRIVER_INTERNAL", "Processor driver internal error"),
    "0x1000007E": ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M", "System thread exception (x64)"),
    "0x1000007F": ("UNEXPECTED_KERNEL_MODE_TRAP_M", "Kernel mode trap (x64)"),
    "0xC000021A": ("STATUS_SYSTEM_PROCESS_TERMINATED", "Winlogon or CSRSS terminated"),
    "0xC0000221": ("STATUS_IMAGE_CHECKSUM_MISMATCH", "Driver or DLL corruption"),
}

# Critical Event IDs
CRITICAL_EVENT_IDS = {
    # System
    41: ("Kernel-Power", "System rebooted without clean shutdown"),
    6008: ("EventLog", "Unexpected shutdown"),
    1074: ("User32", "System shutdown/restart"),
    1076: ("User32", "Shutdown reason"),
    
    # Application crashes
    1000: ("Application Error", "Application crash"),
    1001: ("Application Error", "Application hang"),
    1002: ("Application Hang", "Application hang detected"),
    
    # BSOD
    1001: ("BugCheck", "BSOD occurred"),
    
    # Disk
    7: ("Disk", "Bad block"),
    9: ("Disk", "Device timeout"),
    11: ("Disk", "Controller error"),
    15: ("Disk", "Device not ready"),
    50: ("Disk", "Paging file error"),
    51: ("Disk", "Error during paging"),
    55: ("NTFS", "File system corruption"),
    57: ("NTFS", "Disk full"),
    137: ("NTFS", "Disk corruption detected"),
    
    # Memory
    2004: ("Resource-Exhaustion-Detector", "Memory exhaustion"),
    2019: ("Srv", "Server out of memory"),
    2020: ("Srv", "Server out of paged pool"),
    
    # Driver
    219: ("Kernel-PnP", "Driver failed to load"),
    220: ("Kernel-PnP", "Driver load collision"),
    
    # Security
    4624: ("Security", "Successful logon"),
    4625: ("Security", "Failed logon"),
    4648: ("Security", "Explicit credential logon"),
    4672: ("Security", "Special privileges assigned"),
    4720: ("Security", "User account created"),
    4726: ("Security", "User account deleted"),
    4740: ("Security", "Account locked out"),
    4768: ("Security", "Kerberos authentication"),
    4771: ("Security", "Kerberos pre-authentication failed"),
    4776: ("Security", "NTLM authentication"),
    4788: ("Security", "Account password changed"),
    
    # Windows Update
    20: ("WindowsUpdateClient", "Installation started"),
    21: ("WindowsUpdateClient", "Installation successful"),
    22: ("WindowsUpdateClient", "Installation failed"),
    23: ("WindowsUpdateClient", "Installation restarted"),
    24: ("WindowsUpdateClient", "Installation cancelled"),
    25: ("WindowsUpdateClient", "Uninstallation started"),
    26: ("WindowsUpdateClient", "Uninstallation successful"),
    27: ("WindowsUpdateClient", "Uninstallation failed"),
    44: ("WindowsUpdateClient", "Update requested"),
    
    # Service Control Manager
    7000: ("Service Control Manager", "Service failed to start"),
    7001: ("Service Control Manager", "Service dependency failed"),
    7009: ("Service Control Manager", "Service timeout"),
    7011: ("Service Control Manager", "Service timeout"),
    7022: ("Service Control Manager", "Service hung"),
    7023: ("Service Control Manager", "Service terminated"),
    7024: ("Service Control Manager", "Service terminated with error"),
    7026: ("Service Control Manager", "Boot-start driver load failed"),
    7031: ("Service Control Manager", "Service crashed"),
    7032: ("Service Control Manager", "Service recovery action"),
    7034: ("Service Control Manager", "Service terminated unexpectedly"),
}

@dataclass
class EventEntry:
    timestamp: datetime
    level: str
    source: str
    event_id: int
    category: str
    message: str
    computer: str
    user: str
    xml_data: Optional[str] = None
    
@dataclass
class MinidumpInfo:
    filename: str
    path: str
    size: int
    created: datetime
    modified: datetime
    bugcheck_code: str
    bugcheck_name: str
    bugcheck_desc: str
    caused_by: str
    process_name: str
    crash_address: str
    stack_trace: List[str]
    drivers_involved: List[str]
    analysis_complete: bool

@dataclass
class BsodHistoryEntry:
    timestamp: datetime
    bugcheck_code: str
    bugcheck_name: str
    description: str
    minidump_file: Optional[str]
    related_events: List[EventEntry]

class EventLogReader:
    """Reads Windows Event Logs"""
    
    LOG_NAMES = {
        "System": "System",
        "Application": "Application",
        "Security": "Security",
        "Setup": "Setup",
        "ForwardedEvents": "ForwardedEvents",
        "HardwareEvents": "HardwareEvents",
        "Microsoft-Windows-WindowsUpdateClient/Operational": "WindowsUpdate",
        "Microsoft-Windows-Kernel-PnP/Operational": "PlugAndPlay",
        "Microsoft-Windows-DeviceSetupManager/Admin": "DeviceSetup",
        "Microsoft-Windows-Windows Defender/Operational": "WindowsDefender",
        "Microsoft-Windows-Power-Troubleshooter/Admin": "Power",
        "Microsoft-Windows-ReliabilityAnalysisComponent/Operational": "Reliability",
    }
    
    @classmethod
    def read_log(cls, log_name: str, hours_back: int = 168, 
                 event_ids: Optional[List[int]] = None,
                 level_filter: Optional[List[int]] = None) -> List[EventEntry]:
        """Read events from specified log"""
        events = []
        
        if not WINDOWS_MODE:
            return events
            
        try:
            hand = win32evtlog.OpenEventLog(None, log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            total = win32evtlog.GetNumberOfEventLogRecords(hand)
            cutoff_time = datetime.now() - timedelta(hours=hours_back)
            
            while True:
                records = win32evtlog.ReadEventLog(hand, flags, 0)
                if not records:
                    break
                    
                for record in records:
                    try:
                        # Check time filter
                        event_time = record.TimeGenerated
                        if isinstance(event_time, str):
                            event_time = datetime.strptime(event_time, "%Y-%m-%d %H:%M:%S")
                            
                        if event_time < cutoff_time:
                            win32evtlog.CloseEventLog(hand)
                            return events
                            
                        # Check event ID filter
                        if event_ids and record.EventID not in event_ids:
                            continue
                            
                        # Check level filter
                        if level_filter and record.EventType not in level_filter:
                            continue
                            
                        # Get message
                        try:
                            msg = win32evtlogutil.SafeFormatMessage(record, log_name)
                        except:
                            msg = str(record.StringInserts) if record.StringInserts else "No message"
                            
                        entry = EventEntry(
                            timestamp=event_time,
                            level=cls._get_level_name(record.EventType),
                            source=record.SourceName,
                            event_id=record.EventID & 0xFFFF,
                            category=record.EventCategory,
                            message=msg[:2000] if msg else "No message",
                            computer=record.ComputerName,
                            user=record.Sid if record.Sid else "N/A"
                        )
                        
                        events.append(entry)
                        
                    except Exception as e:
                        continue
                        
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            print(f"Error reading {log_name}: {e}")
            
        return events
    
    @classmethod
    def read_all_critical(cls, hours_back: int = 168) -> Dict[str, List[EventEntry]]:
        """Read all critical events from all logs"""
        results = {}
        
        # Critical system events
        critical_ids = [id for id, _ in CRITICAL_EVENT_IDS.items()]
        
        for log_name in ["System", "Application"]:
            events = cls.read_log(log_name, hours_back, critical_ids)
            if events:
                results[log_name] = events
                
        # Security events (if accessible)
        try:
            sec_events = cls.read_log("Security", hours_back, [4625, 4648, 4672, 4740, 4771])
            if sec_events:
                results["Security"] = sec_events
        except:
            pass
            
        return results
    
    @classmethod
    def _get_level_name(cls, event_type: int) -> str:
        levels = {
            win32con.EVENTLOG_SUCCESS: "Success",
            win32con.EVENTLOG_ERROR_TYPE: "Error",
            win32con.EVENTLOG_WARNING_TYPE: "Warning",
            win32con.EVENTLOG_INFORMATION_TYPE: "Information",
            win32con.EVENTLOG_AUDIT_SUCCESS: "Audit Success",
            win32con.EVENTLOG_AUDIT_FAILURE: "Audit Failure",
        }
        return levels.get(event_type, "Unknown")

class MinidumpAnalyzer:
    """Analyzes Windows minidump files"""
    
    DUMP_PATHS = [
        r"C:\Windows\Minidump",
        r"C:\Windows\LiveKernelReports",
        r"C:\Windows\MEMORY.DMP",
    ]
    
    @classmethod
    def find_dumps(cls) -> List[str]:
        """Find all minidump files"""
        dumps = []
        
        for path in cls.DUMP_PATHS:
            if os.path.isdir(path):
                dumps.extend(glob.glob(os.path.join(path, "*.dmp")))
                dumps.extend(glob.glob(os.path.join(path, "*.mdmp")))
            elif os.path.isfile(path):
                dumps.append(path)
                
        # Sort by modification time (newest first)
        dumps.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        return dumps
    
    @classmethod
    def analyze_dump(cls, dump_path: str) -> MinidumpInfo:
        """Analyze a minidump file"""
        info = MinidumpInfo(
            filename=os.path.basename(dump_path),
            path=dump_path,
            size=os.path.getsize(dump_path),
            created=datetime.fromtimestamp(os.path.getctime(dump_path)),
            modified=datetime.fromtimestamp(os.path.getmtime(dump_path)),
            bugcheck_code="Unknown",
            bugcheck_name="Unknown",
            bugcheck_desc="Analysis pending",
            caused_by="Unknown",
            process_name="Unknown",
            crash_address="Unknown",
            stack_trace=[],
            drivers_involved=[],
            analysis_complete=False
        )
        
        # Try to use cdb.exe if available
        cdb_paths = [
            r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
            r"C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe",
            r"C:\Program Files (x86)\Windows Kits\11\Debuggers\x64\cdb.exe",
            r"C:\Program Files\Windows Kits\11\Debuggers\x64\cdb.exe",
        ]
        
        cdb = None
        for path in cdb_paths:
            if os.path.exists(path):
                cdb = path
                break
                
        if cdb:
            try:
                cls._analyze_with_cdb(info, cdb, dump_path)
            except Exception as e:
                info.bugcheck_desc = f"CDB analysis failed: {e}"
                
        # Fallback: try to extract basic info from filename or header
        if not info.analysis_complete:
            cls._basic_analysis(info, dump_path)
            
        return info
    
    @classmethod
    def _analyze_with_cdb(cls, info: MinidumpInfo, cdb: str, dump_path: str):
        """Analyze using Windows Debugging Tools"""
        cmd = [
            cdb,
            "-z", dump_path,
            "-c", "!analyze -v;q",
            "-logo", "nul"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout
        
        # Parse bug check code
        bc_match = re.search(r'BUGCHECK_CODE:\s+([0-9a-fA-Fx]+)', output)
        if bc_match:
            code = bc_match.group(1).lower()
            if not code.startswith('0x'):
                code = f"0x{code.zfill(8)}"
            info.bugcheck_code = code
            
            # Look up name and description
            if code.upper() in BSOD_CODES:
                info.bugcheck_name, info.bugcheck_desc = BSOD_CODES[code.upper()]
            else:
                info.bugcheck_name = "Unknown Error"
                info.bugcheck_desc = "Unknown bug check code"
                
        # Parse process name
        proc_match = re.search(r'PROCESS_NAME:\s+(\S+)', output)
        if proc_match:
            info.process_name = proc_match.group(1)
            
        # Parse caused by driver
        img_match = re.search(r'IMAGE_NAME:\s+(\S+)', output)
        if img_match:
            info.caused_by = img_match.group(1)
            
        # Parse crash address
        addr_match = re.search(r'FAILURE_BUCKET_ID:[^\n]*?\+([0-9a-fA-Fx]+)', output)
        if addr_match:
            info.crash_address = addr_match.group(1)
            
        # Extract stack trace
        stack_started = False
        for line in output.split('\n'):
            if "STACK_TEXT:" in line:
                stack_started = True
                continue
            if stack_started and line.strip() and not line.startswith('0:'):
                if len(info.stack_trace) < 10:
                    info.stack_trace.append(line.strip())
                else:
                    break
                    
        # Extract driver references
        driver_pattern = r'([a-zA-Z0-9_]+\.(sys|dll|exe))'
        drivers = set(re.findall(driver_pattern, output))
        info.drivers_involved = [d[0] for d in drivers][:10]
        
        info.analysis_complete = True
    
    @classmethod
    def _basic_analysis(cls, info: MinidumpInfo, dump_path: str):
        """Basic analysis without debugging tools"""
        # Try to read first few bytes for signature
        try:
            with open(dump_path, 'rb') as f:
                header = f.read(100)
                
            # Look for bug check code in binary
            # This is a simplified heuristic
            if b'MINIDUMP' in header:
                info.bugcheck_desc = "Minidump format detected (detailed analysis requires Windows SDK)"
            else:
                info.bugcheck_desc = "Full memory dump (analysis requires Windows SDK)"
                
        except:
            info.bugcheck_desc = "Unable to read dump file"

class BsodAnalyzer:
    """Analyzes BSOD history and patterns"""
    
    @classmethod
    def get_bsod_history(cls, days_back: int = 30) -> List[BsodHistoryEntry]:
        """Get complete BSOD history from events and dumps"""
        history = []
        
        if not WINDOWS_MODE:
            return history
            
        # Find minidumps
        dumps = MinidumpAnalyzer.find_dumps()
        analyzed_dumps = {d.path: d for d in [MinidumpAnalyzer.analyze_dump(p) for p in dumps]}
        
        # Get System events related to crashes
        cutoff = datetime.now() - timedelta(days=days_back)
        
        # Look for Event ID 1001 (BugCheck)
        bugcheck_events = EventLogReader.read_log(
            "System", 
            days_back * 24,
            event_ids=[1001]
        )
        
        # Also look for kernel-power events (unexpected shutdowns)
        power_events = EventLogReader.read_log(
            "System",
            days_back * 24,
            event_ids=[41, 6008]
        )
        
        # Match dumps with events
        processed_dumps = set()
        
        for event in bugcheck_events:
            try:
                # Parse bug check info from event
                code = cls._extract_bugcheck_from_event(event)
                
                # Find matching dump
                matching_dump = None
                for path, dump in analyzed_dumps.items():
                    time_diff = abs((dump.created - event.timestamp).total_seconds())
                    if time_diff < 300:  # Within 5 minutes
                        matching_dump = dump
                        processed_dumps.add(path)
                        break
                        
                entry = BsodHistoryEntry(
                    timestamp=event.timestamp,
                    bugcheck_code=code if code else (matching_dump.bugcheck_code if matching_dump else "Unknown"),
                    bugcheck_name=matching_dump.bugcheck_name if matching_dump else "Unknown",
                    description=matching_dump.bugcheck_desc if matching_dump else event.message[:200],
                    minidump_file=matching_dump.filename if matching_dump else None,
                    related_events=cls._find_related_events(event, power_events)
                )
                
                history.append(entry)
                
            except Exception as e:
                print(f"Error processing BSOD event: {e}")
                
        # Add dumps without matching events
        for path, dump in analyzed_dumps.items():
            if path not in processed_dumps and dump.created > cutoff:
                entry = BsodHistoryEntry(
                    timestamp=dump.created,
                    bugcheck_code=dump.bugcheck_code,
                    bugcheck_name=dump.bugcheck_name,
                    description=dump.bugcheck_desc,
                    minidump_file=dump.filename,
                    related_events=[]
                )
                history.append(entry)
                
        # Sort by timestamp
        history.sort(key=lambda x: x.timestamp, reverse=True)
        return history
    
    @classmethod
    def _extract_bugcheck_from_event(cls, event: EventEntry) -> Optional[str]:
        """Extract bug check code from event message"""
        patterns = [
            r'0x[0-9a-fA-F]{8}',  # Standard hex format
            r'bugcheck\s+([0-9a-fA-F]+)',  # Text format
        ]
        
        for pattern in patterns:
            match = re.search(pattern, event.message, re.IGNORECASE)
            if match:
                code = match.group(0)
                if not code.startswith('0x'):
                    code = f"0x{code.zfill(8)}"
                return code.upper()
                
        return None
    
    @classmethod
    def _find_related_events(cls, target_event: EventEntry, 
                            all_events: List[EventEntry]) -> List[EventEntry]:
        """Find events related to a BSOD"""
        related = []
        time_window = 300  # 5 minutes before/after
        
        for event in all_events:
            if event == target_event:
                continue
                
            time_diff = abs((event.timestamp - target_event.timestamp).total_seconds())
            if time_diff < time_window:
                related.append(event)
                
        return related
    
    @classmethod
    def analyze_patterns(cls, history: List[BsodHistoryEntry]) -> Dict[str, Any]:
        """Analyze patterns in BSOD history"""
        if not history:
            return {"error": "No BSOD history found"}
            
        patterns = {
            "total_crashes": len(history),
            "time_range": {
                "first": history[-1].timestamp if history else None,
                "last": history[0].timestamp if history else None
            },
            "common_codes": {},
            "frequency_by_day": defaultdict(int),
            "drivers_involved": defaultdict(int),
            "recommendations": []
        }
        
        for entry in history:
            # Count bug check codes
            code = entry.bugcheck_code
            patterns["common_codes"][code] = patterns["common_codes"].get(code, 0) + 1
            
            # Count by day
            day_key = entry.timestamp.strftime("%Y-%m-%d")
            patterns["frequency_by_day"][day_key] += 1
            
        # Find most common code
        if patterns["common_codes"]:
            most_common = max(patterns["common_codes"].items(), key=lambda x: x[1])
            patterns["most_common_code"] = most_common
            
            # Add recommendations based on common code
            code = most_common[0]
            if code in BSOD_CODES:
                _, desc = BSOD_CODES[code]
                if "memory" in desc.lower():
                    patterns["recommendations"].append("Run memory diagnostic (RAM issue suspected)")
                if "driver" in desc.lower():
                    patterns["recommendations"].append("Update all device drivers")
                if "disk" in desc.lower() or "ntfs" in desc.lower():
                    patterns["recommendations"].append("Check disk for errors and bad sectors")
                if "gpu" in desc.lower() or "video" in desc.lower():
                    patterns["recommendations"].append("Update graphics drivers and check GPU temperature")
                    
        # Time-based analysis
        if len(history) > 1:
            dates = [h.timestamp for h in history]
            span = (max(dates) - min(dates)).days
            if span > 0:
                frequency = len(history) / span
                patterns["crashes_per_day"] = frequency
                
                if frequency > 1:
                    patterns["recommendations"].append("CRITICAL: Frequent crashes detected - check hardware immediately")
                elif frequency > 0.5:
                    patterns["recommendations"].append("WARNING: Regular crashes detected - investigate soon")
                    
        return patterns

class EventTableModel(QAbstractTableModel):
    """Model for event table display"""
    
    COLUMNS = ["Time", "Level", "Source", "ID", "Message"]
    
    def __init__(self, events: List[EventEntry] = None):
        super().__init__()
        self.events = events or []
        self.filtered_events = self.events.copy()
        
    def set_events(self, events: List[EventEntry]):
        self.beginResetModel()
        self.events = events
        self.filtered_events = events
        self.endResetModel()
        
    def filter_events(self, text: str, level: Optional[str] = None):
        self.beginResetModel()
        self.filtered_events = []
        
        for event in self.events:
            match = True
            
            if text:
                search_text = text.lower()
                if (search_text not in event.message.lower() and 
                    search_text not in event.source.lower() and
                    search_text not in str(event.event_id)):
                    match = False
                    
            if level and event.level != level:
                match = False
                
            if match:
                self.filtered_events.append(event)
                
        self.endResetModel()
        
    def rowCount(self, parent=QModelIndex()):
        return len(self.filtered_events)
        
    def columnCount(self, parent=QModelIndex()):
        return len(self.COLUMNS)
        
    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or index.row() >= len(self.filtered_events):
            return None
            
        event = self.filtered_events[index.row()]
        col = index.column()
        
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            elif col == 1:
                return event.level
            elif col == 2:
                return event.source
            elif col == 3:
                return str(event.event_id)
            elif col == 4:
                return event.message[:100] + "..." if len(event.message) > 100 else event.message
                
        elif role == Qt.ItemDataRole.ForegroundRole:
            if event.level == "Error":
                return QColor("#ef4444")
            elif event.level == "Warning":
                return QColor("#f59e0b")
            elif event.level == "Information":
                return QColor("#3b82f6")
                
        return None
        
    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.COLUMNS[section]
        return None
        
    def get_event(self, row: int) -> Optional[EventEntry]:
        if 0 <= row < len(self.filtered_events):
            return self.filtered_events[row]
        return None

class EventAnalyzerWidget(QWidget):
    """Main event analyzer widget"""
    
    def __init__(self):
        super().__init__()
        self.events = []
        self.bsod_history = []
        self.minidumps = []
        self.current_filter = ""
        
        self.setup_ui()
        self.load_initial_data()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)
        
        # Header
        header = QLabel("Event Log & BSOD Analyzer")
        header.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        header.setStyleSheet("color: #f8fafc;")
        layout.addWidget(header)
        
        # Main tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #334155;
                border-radius: 8px;
                background-color: #1e293b;
            }
            QTabBar::tab {
                background-color: #334155;
                color: #94a3b8;
                padding: 10px 20px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
            }
            QTabBar::tab:selected {
                background-color: #0ea5e9;
                color: white;
            }
        """)
        
        # Tab 1: Event Viewer
        self.setup_event_tab()
        
        # Tab 2: BSOD History
        self.setup_bsod_tab()
        
        # Tab 3: Minidump Analyzer
        self.setup_minidump_tab()
        
        # Tab 4: Pattern Analysis
        self.setup_pattern_tab()
        
        layout.addWidget(self.tabs)
        
        # Status bar
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #94a3b8; padding: 5px;")
        layout.addWidget(self.status_label)
        
        # Styling
        self.setStyleSheet("""
            QWidget {
                background-color: #0f172a;
            }
            QLabel {
                color: #f8fafc;
            }
            QPushButton {
                background-color: #334155;
                color: #f8fafc;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #475569;
            }
            QLineEdit {
                background-color: #1e293b;
                color: #f8fafc;
                border: 1px solid #334155;
                border-radius: 4px;
                padding: 6px;
            }
            QComboBox {
                background-color: #1e293b;
                color: #f8fafc;
                border: 1px solid #334155;
                border-radius: 4px;
                padding: 6px;
            }
        """)
        
    def setup_event_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.log_combo = QComboBox()
        self.log_combo.addItems(["System", "Application", "Security", "Setup", "All"])
        toolbar.addWidget(QLabel("Log:"))
        toolbar.addWidget(self.log_combo)
        
        self.time_combo = QComboBox()
        self.time_combo.addItems(["Last 24 hours", "Last 7 days", "Last 30 days", "Last 90 days", "All time"])
        toolbar.addWidget(QLabel("Time:"))
        toolbar.addWidget(self.time_combo)
        
        self.level_combo = QComboBox()
        self.level_combo.addItems(["All levels", "Error", "Warning", "Information"])
        toolbar.addWidget(QLabel("Level:"))
        toolbar.addWidget(self.level_combo)
        
        toolbar.addStretch()
        
        self.btn_load_events = QPushButton("🔄 Load Events")
        self.btn_load_events.clicked.connect(self.load_events)
        toolbar.addWidget(self.btn_load_events)
        
        self.btn_export_events = QPushButton("📄 Export")
        self.btn_export_events.clicked.connect(self.export_events)
        toolbar.addWidget(self.btn_export_events)
        
        layout.addLayout(toolbar)
        
        # Filter
        filter_layout = QHBoxLayout()
        self.event_filter = QLineEdit()
        self.event_filter.setPlaceholderText("Filter events...")
        self.event_filter.textChanged.connect(self.filter_events)
        filter_layout.addWidget(self.event_filter)
        layout.addLayout(filter_layout)
        
        # Event table
        self.event_table = QTableWidget()
        self.event_table.setColumnCount(5)
        self.event_table.setHorizontalHeaderLabels(["Time", "Level", "Source", "ID", "Message"])
        self.event_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.event_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.event_table.setStyleSheet("""
            QTableWidget {
                background-color: #1e293b;
                border: 1px solid #334155;
                color: #f8fafc;
                gridline-color: #334155;
            }
            QHeaderView::section {
                background-color: #334155;
                color: #f8fafc;
                padding: 8px;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 6px;
            }
        """)
        self.event_table.itemSelectionChanged.connect(self.on_event_selected)
        layout.addWidget(self.event_table)
        
        # Event details
        self.event_details = QTextEdit()
        self.event_details.setReadOnly(True)
        self.event_details.setMaximumHeight(150)
        self.event_details.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #cbd5e1;
                border: 1px solid #334155;
                border-radius: 6px;
                font-family: 'Consolas', monospace;
            }
        """)
        layout.addWidget(self.event_details)
        
        self.tabs.addTab(tab, "Event Viewer")
        
    def setup_bsod_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.bsod_time_combo = QComboBox()
        self.bsod_time_combo.addItems(["Last 7 days", "Last 30 days", "Last 90 days", "All time"])
        toolbar.addWidget(QLabel("Period:"))
        toolbar.addWidget(self.bsod_time_combo)
        
        toolbar.addStretch()
        
        self.btn_refresh_bsod = QPushButton("🔄 Refresh")
        self.btn_refresh_bsod.clicked.connect(self.load_bsod_history)
        toolbar.addWidget(self.btn_refresh_bsod)
        
        self.btn_analyze_bsod = QPushButton("🔍 Analyze Patterns")
        self.btn_analyze_bsod.clicked.connect(self.analyze_bsod_patterns)
        toolbar.addWidget(self.btn_analyze_bsod)
        
        layout.addLayout(toolbar)
        
        # BSOD table
        self.bsod_table = QTableWidget()
        self.bsod_table.setColumnCount(5)
        self.bsod_table.setHorizontalHeaderLabels(["Time", "Error Code", "Error Name", "Description", "Dump File"])
        self.bsod_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.bsod_table.setStyleSheet("""
            QTableWidget {
                background-color: #1e293b;
                border: 1px solid #334155;
                color: #f8fafc;
            }
            QHeaderView::section {
                background-color: #334155;
                color: #f8fafc;
                padding: 8px;
            }
        """)
        self.bsod_table.itemSelectionChanged.connect(self.on_bsod_selected)
        layout.addWidget(self.bsod_table)
        
        # BSOD details
        self.bsod_details = QTextEdit()
        self.bsod_details.setReadOnly(True)
        self.bsod_details.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #cbd5e1;
                border: 1px solid #334155;
                border-radius: 6px;
            }
        """)
        layout.addWidget(self.bsod_details)
        
        self.tabs.addTab(tab, "BSOD History")
        
    def setup_minidump_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.btn_scan_dumps = QPushButton("🔍 Scan for Dumps")
        self.btn_scan_dumps.clicked.connect(self.scan_minidumps)
        toolbar.addWidget(self.btn_scan_dumps)
        
        self.btn_analyze_dump = QPushButton("📊 Analyze Selected")
        self.btn_analyze_dump.clicked.connect(self.analyze_selected_dump)
        toolbar.addWidget(self.btn_analyze_dump)
        
        self.btn_install_sdk = QPushButton("⬇ Install Debugging Tools")
        self.btn_install_sdk.clicked.connect(self.install_debugging_tools)
        toolbar.addWidget(self.btn_install_sdk)
        
        toolbar.addStretch()
        
        self.btn_open_dump_dir = QPushButton("📁 Open Directory")
        self.btn_open_dump_dir.clicked.connect(self.open_dump_directory)
        toolbar.addWidget(self.btn_open_dump_dir)
        
        layout.addLayout(toolbar)
        
        # Dump table
        self.dump_table = QTableWidget()
        self.dump_table.setColumnCount(6)
        self.dump_table.setHorizontalHeaderLabels(["File", "Date", "Size", "Type", "Status", "Bug Check"])
        self.dump_table.setStyleSheet("""
            QTableWidget {
                background-color: #1e293b;
                border: 1px solid #334155;
                color: #f8fafc;
            }
        """)
        layout.addWidget(self.dump_table)
        
        # Dump analysis output
        self.dump_analysis = QTextEdit()
        self.dump_analysis.setReadOnly(True)
        self.dump_analysis.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #cbd5e1;
                border: 1px solid #334155;
                border-radius: 6px;
                font-family: 'Consolas', monospace;
            }
        """)
        layout.addWidget(self.dump_analysis)
        
        self.tabs.addTab(tab, "Minidump Analyzer")
        
    def setup_pattern_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Analysis results
        self.pattern_text = QTextEdit()
        self.pattern_text.setReadOnly(True)
        self.pattern_text.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #cbd5e1;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 10px;
                font-size: 13px;
            }
        """)
        layout.addWidget(self.pattern_text)
        
        # Common BSOD codes reference
        ref_group = QGroupBox("BSOD Code Reference")
        ref_group.setStyleSheet("""
            QGroupBox {
                color: #38bdf8;
                font-weight: bold;
                border: 1px solid #334155;
                border-radius: 8px;
            }
        """)
        ref_layout = QVBoxLayout(ref_group)
        
        ref_text = QTextEdit()
        ref_text.setReadOnly(True)
        ref_text.setMaximumHeight(200)
        ref_text.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #94a3b8;
                border: none;
                font-family: 'Consolas', monospace;
                font-size: 11px;
            }
        """)
        
        # Build reference text
        ref_lines = []
        for code, (name, desc) in list(BSOD_CODES.items())[:20]:
            ref_lines.append(f"<b>{code}</b> - {name}<br>&nbsp;&nbsp;{desc}<br>")
        ref_text.setHtml("<br>".join(ref_lines))
        
        ref_layout.addWidget(ref_text)
        layout.addWidget(ref_group)
        
        self.tabs.addTab(tab, "Pattern Analysis")
        
    def load_initial_data(self):
        """Load data on startup"""
        self.load_bsod_history()
        self.scan_minidumps()
        
    def load_events(self):
        """Load events from selected log"""
        log_name = self.log_combo.currentText()
        time_text = self.time_combo.currentText()
        
        # Parse time range
        hours = {
            "Last 24 hours": 24,
            "Last 7 days": 168,
            "Last 30 days": 720,
            "Last 90 days": 2160,
            "All time": 8760
        }.get(time_text, 168)
        
        self.status_label.setText(f"Loading {log_name} events...")
        
        if log_name == "All":
            # Load critical events from all logs
            events = []
            for log in ["System", "Application"]:
                events.extend(EventLogReader.read_log(log, hours))
        else:
            events = EventLogReader.read_log(log_name, hours)
            
        self.events = events
        self.populate_event_table(events)
        self.status_label.setText(f"Loaded {len(events)} events")
        
    def populate_event_table(self, events: List[EventEntry]):
        """Populate event table"""
        self.event_table.setRowCount(0)
        
        for event in events:
            row = self.event_table.rowCount()
            self.event_table.insertRow(row)
            
            # Time
            time_item = QTableWidgetItem(event.timestamp.strftime("%Y-%m-%d %H:%M"))
            self.event_table.setItem(row, 0, time_item)
            
            # Level with color
            level_item = QTableWidgetItem(event.level)
            if event.level == "Error":
                level_item.setForeground(QColor("#ef4444"))
            elif event.level == "Warning":
                level_item.setForeground(QColor("#f59e0b"))
            elif event.level == "Information":
                level_item.setForeground(QColor("#3b82f6"))
            self.event_table.setItem(row, 1, level_item)
            
            self.event_table.setItem(row, 2, QTableWidgetItem(event.source))
            self.event_table.setItem(row, 3, QTableWidgetItem(str(event.event_id)))
            
            # Truncated message
            msg = event.message[:80] + "..." if len(event.message) > 80 else event.message
            self.event_table.setItem(row, 4, QTableWidgetItem(msg))
            
    def filter_events(self, text: str):
        """Filter events based on search text"""
        if not text:
            self.populate_event_table(self.events)
            return
            
        filtered = []
        search_lower = text.lower()
        
        for event in self.events:
            if (search_lower in event.message.lower() or 
                search_lower in event.source.lower() or
                search_lower in str(event.event_id)):
                filtered.append(event)
                
        self.populate_event_table(filtered)
        
    def on_event_selected(self):
        """Show event details"""
        selected = self.event_table.selectedItems()
        if not selected:
            return
            
        row = selected[0].row()
        if row < len(self.events):
            event = self.events[row]
            
            details = f"""
<b>Time:</b> {event.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
<b>Level:</b> {event.level}
<b>Source:</b> {event.source}
<b>Event ID:</b> {event.event_id}
<b>Computer:</b> {event.computer}
<b>User:</b> {event.user}

<b>Message:</b>
{event.message}
            """
            self.event_details.setHtml(details)
            
    def load_bsod_history(self):
        """Load BSOD history"""
        time_text = self.bsod_time_combo.currentText()
        days = {
            "Last 7 days": 7,
            "Last 30 days": 30,
            "Last 90 days": 90,
            "All time": 365
        }.get(time_text, 30)
        
        self.status_label.setText("Loading BSOD history...")
        self.bsod_history = BsodAnalyzer.get_bsod_history(days)
        
        self.bsod_table.setRowCount(0)
        
        for entry in self.bsod_history:
            row = self.bsod_table.rowCount()
            self.bsod_table.insertRow(row)
            
            self.bsod_table.setItem(row, 0, QTableWidgetItem(
                entry.timestamp.strftime("%Y-%m-%d %H:%M")))
            
            code_item = QTableWidgetItem(entry.bugcheck_code)
            code_item.setForeground(QColor("#f59e0b"))
            self.bsod_table.setItem(row, 1, code_item)
            
            self.bsod_table.setItem(row, 2, QTableWidgetItem(entry.bugcheck_name))
            
            desc = entry.description[:60] + "..." if len(entry.description) > 60 else entry.description
            self.bsod_table.setItem(row, 3, QTableWidgetItem(desc))
            
            dump_text = entry.minidump_file if entry.minidump_file else "None"
            self.bsod_table.setItem(row, 4, QTableWidgetItem(dump_text))
            
        self.status_label.setText(f"Found {len(self.bsod_history)} BSOD events")
        
    def on_bsod_selected(self):
        """Show BSOD details"""
        selected = self.bsod_table.selectedItems()
        if not selected:
            return
            
        row = selected[0].row()
        if row < len(self.bsod_history):
            entry = self.bsod_history[row]
            
            details = f"""
<h3>BSOD Details</h3>
<b>Time:</b> {entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
<b>Error Code:</b> {entry.bugcheck_code}
<b>Error Name:</b> {entry.bugcheck_name}
<b>Description:</b> {entry.description}

<b>Minidump File:</b> {entry.minidump_file if entry.minidump_file else "Not available"}

<b>Related Events:</b>
"""
            if entry.related_events:
                for evt in entry.related_events:
                    details += f"<br>• [{evt.timestamp.strftime('%H:%M:%S')}] {evt.source}: {evt.message[:100]}"
            else:
                details += "<br>No related events found"
                
            # Add recommendations
            details += "<br><br><b>Recommendations:</b>"
            if entry.bugcheck_code in BSOD_CODES:
                _, desc = BSOD_CODES[entry.bugcheck_code]
                if "memory" in desc.lower():
                    details += "<br>• Run Windows Memory Diagnostic"
                if "driver" in desc.lower():
                    details += "<br>• Update device drivers"
                if "disk" in desc.lower():
                    details += "<br>• Check disk for errors"
                    
            self.bsod_details.setHtml(details)
            
    def analyze_bsod_patterns(self):
        """Analyze BSOD patterns"""
        if not self.bsod_history:
            self.pattern_text.setText("No BSOD history to analyze")
            return
            
        patterns = BsodAnalyzer.analyze_patterns(self.bsod_history)
        
        text = f"""
<h2>BSOD Pattern Analysis</h2>

<b>Total Crashes:</b> {patterns['total_crashes']}
<b>Time Range:</b> {patterns['time_range']['first'].strftime('%Y-%m-%d') if patterns['time_range']['first'] else 'N/A'} to {patterns['time_range']['last'].strftime('%Y-%m-%d') if patterns['time_range']['last'] else 'N/A'}

<h3>Common Error Codes:</h3>
"""
        for code, count in sorted(patterns['common_codes'].items(), key=lambda x: x[1], reverse=True):
            name = BSOD_CODES.get(code, ("Unknown", ""))[0]
            text += f"• <b>{code}</b> ({name}): {count} times<br>"
            
        if 'crashes_per_day' in patterns:
            text += f"<br><b>Average Frequency:</b> {patterns['crashes_per_day']:.2f} crashes per day"
            
        text += "<br><h3>Recommendations:</h3>"
        if patterns['recommendations']:
            for rec in patterns['recommendations']:
                text += f"• {rec}<br>"
        else:
            text += "• No specific recommendations - crashes appear random<br>"
            
        self.pattern_text.setHtml(text)
        
    def scan_minidumps(self):
        """Scan for minidump files"""
        self.status_label.setText("Scanning for minidumps...")
        dump_paths = MinidumpAnalyzer.find_dumps()
        
        self.dump_table.setRowCount(0)
        self.minidumps = []
        
        for path in dump_paths:
            info = MinidumpInfo(
                filename=os.path.basename(path),
                path=path,
                size=os.path.getsize(path),
                created=datetime.fromtimestamp(os.path.getctime(path)),
                modified=datetime.fromtimestamp(os.path.getmtime(path)),
                bugcheck_code="Unknown",
                bugcheck_name="Not analyzed",
                bugcheck_desc="",
                caused_by="Unknown",
                process_name="Unknown",
                crash_address="Unknown",
                stack_trace=[],
                drivers_involved=[],
                analysis_complete=False
            )
            self.minidumps.append(info)
            
            row = self.dump_table.rowCount()
            self.dump_table.insertRow(row)
            
            self.dump_table.setItem(row, 0, QTableWidgetItem(info.filename))
            self.dump_table.setItem(row, 1, QTableWidgetItem(
                info.modified.strftime("%Y-%m-%d %H:%M")))
            
            size_text = f"{info.size / 1024:.1f} KB" if info.size < 1024*1024 else f"{info.size / (1024*1024):.2f} MB"
            self.dump_table.setItem(row, 2, QTableWidgetItem(size_text))
            
            dump_type = "Minidump" if "minidump" in path.lower() else "Full Dump"
            self.dump_table.setItem(row, 3, QTableWidgetItem(dump_type))
            
            self.dump_table.setItem(row, 4, QTableWidgetItem("Not analyzed"))
            self.dump_table.setItem(row, 5, QTableWidgetItem("Unknown"))
            
        self.status_label.setText(f"Found {len(self.minidumps)} dump files")
        
    def analyze_selected_dump(self):
        """Analyze selected minidump"""
        selected = self.dump_table.selectedItems()
        if not selected:
            QMessageBox.information(self, "Select Dump", "Please select a dump file to analyze")
            return
            
        row = selected[0].row()
        if row >= len(self.minidumps):
            return
            
        dump_info = self.minidumps[row]
        
        self.status_label.setText(f"Analyzing {dump_info.filename}...")
        
        # Perform analysis
        analyzed = MinidumpAnalyzer.analyze_dump(dump_info.path)
        self.minidumps[row] = analyzed
        
        # Update table
        self.dump_table.setItem(row, 4, QTableWidgetItem(
            "Analyzed" if analyzed.analysis_complete else "Basic"))
        self.dump_table.setItem(row, 5, QTableWidgetItem(analyzed.bugcheck_code))
        
        # Show analysis
        analysis_text = f"""
<h3>Minidump Analysis: {analyzed.filename}</h3>

<b>File:</b> {analyzed.path}
<b>Size:</b> {analyzed.size:,} bytes
<b>Created:</b> {analyzed.created.strftime('%Y-%m-%d %H:%M:%S')}

<h4>Crash Information:</h4>
<b>Bug Check Code:</b> {analyzed.bugcheck_code}
<b>Error:</b> {analyzed.bugcheck_name}
<b>Description:</b> {analyzed.bugcheck_desc}
<b>Caused By:</b> {analyzed.caused_by}
<b>Process:</b> {analyzed.process_name}
<b>Crash Address:</b> {analyzed.crash_address}

<h4>Drivers Involved:</h4>
"""
        if analyzed.drivers_involved:
            for driver in analyzed.drivers_involved:
                analysis_text += f"• {driver}<br>"
        else:
            analysis_text += "No driver information available<br>"
            
        if analyzed.stack_trace:
            analysis_text += "<h4>Stack Trace:</h4>"
            for line in analyzed.stack_trace:
                analysis_text += f"{line}<br>"
                
        self.dump_analysis.setHtml(analysis_text)
        self.status_label.setText("Analysis complete")
        
    def install_debugging_tools(self):
        """Open Windows SDK download"""
        import webbrowser
        webbrowser.open("https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/")
        QMessageBox.information(self, "Download", 
                              "Windows SDK download page opened.\n\nInstall 'Debugging Tools for Windows' for detailed dump analysis.")
        
    def open_dump_directory(self):
        """Open minidump directory"""
        dump_dir = r"C:\Windows\Minidump"
        if os.path.exists(dump_dir):
            os.startfile(dump_dir)
        else:
            QMessageBox.warning(self, "Not Found", "Minidump directory not found")
            
    def export_events(self):
        """Export events to file"""
        if not self.events:
            QMessageBox.information(self, "No Data", "No events to export")
            return
            
        path, _ = QFileDialog.getSaveFileName(self, "Export Events", "events.txt", "Text Files (*.txt)")
        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(f"Event Log Export - {datetime.now()}\n")
                    f.write("="*80 + "\n\n")
                    
                    for event in self.events:
                        f.write(f"Time: {event.timestamp}\n")
                        f.write(f"Level: {event.level}\n")
                        f.write(f"Source: {event.source}\n")
                        f.write(f"Event ID: {event.event_id}\n")
                        f.write(f"Message: {event.message}\n")
                        f.write("-"*80 + "\n")
                        
                self.status_label.setText(f"Exported to {path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Export failed: {e}")

class EventAnalyzerWindow(QMainWindow):
    """Standalone window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setMinimumSize(1400, 900)
        
        self.analyzer_widget = EventAnalyzerWidget()
        self.setCentralWidget(self.analyzer_widget)
        
        self.create_menu()
        self.apply_theme()
        
    def create_menu(self):
        menubar = self.menuBar()
        
        file_menu = menubar.addMenu("File")
        
        refresh_action = QAction("Refresh All", self)
        refresh_action.setShortcut("F5")
        refresh_action.triggered.connect(self.refresh_all)
        file_menu.addAction(refresh_action)
        
        file_menu.addSeparator()
        
        export_action = QAction("Export Report...", self)
        export_action.triggered.connect(self.export_report)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        tools_menu = menubar.addMenu("Tools")
        
        event_viewer_action = QAction("Open Event Viewer", self)
        event_viewer_action.triggered.connect(lambda: os.system("eventvwr.msc"))
        tools_menu.addAction(event_viewer_action)
        
        reliability_action = QAction("Reliability Monitor", self)
        reliability_action.triggered.connect(self.open_reliability)
        tools_menu.addAction(reliability_action)
        
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def apply_theme(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0f172a;
            }
            QMenuBar {
                background-color: #1e293b;
                color: #f8fafc;
                border-bottom: 1px solid #334155;
            }
            QMenuBar::item:selected {
                background-color: #334155;
            }
            QMenu {
                background-color: #1e293b;
                color: #f8fafc;
                border: 1px solid #334155;
            }
            QMenu::item:selected {
                background-color: #0ea5e9;
            }
        """)
        
    def refresh_all(self):
        self.analyzer_widget.load_events()
        self.analyzer_widget.load_bsod_history()
        self.analyzer_widget.scan_minidumps()
        
    def export_report(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Report", "bsod_report.html", "HTML Files (*.html)")
        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(f"<html><body style='font-family: Arial; background: #0f172a; color: #f8fafc;'>")
                    f.write(f"<h1>{APP_NAME} Report</h1>")
                    f.write(f"<p>Generated: {datetime.now()}</p>")
                    
                    f.write("<h2>BSOD History</h2>")
                    for entry in self.analyzer_widget.bsod_history:
                        f.write(f"<p><b>{entry.timestamp}</b> - {entry.bugcheck_code} ({entry.bugcheck_name})</p>")
                        
                    f.write("</body></html>")
                    
                QMessageBox.information(self, "Exported", f"Report saved to {path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))
                
    def open_reliability(self):
        try:
            os.system("perfmon /rel")
        except:
            pass
            
    def show_about(self):
        QMessageBox.about(self, f"About {APP_NAME}",
                         f"{APP_NAME} v{APP_VERSION}\n\n"
                         f"Comprehensive Windows event log and BSOD analysis tool.\n\n"
                         f"Features:\n"
                         f"• Event log filtering and analysis\n"
                         f"• BSOD history tracking\n"
                         f"• Minidump analysis\n"
                         f"• Pattern detection\n"
                         f"• Crash forensics")

def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setStyle("Fusion")
    
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    window = EventAnalyzerWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()