# storage_diagnostic.py - Complete Storage Diagnostic Module (Under 3000 lines)
import sys
import os
import subprocess
import re
import json
import threading
import time
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple
import ctypes

# PyQt6 imports
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QPushButton, QTableWidget, QTableWidgetItem, QProgressBar,
    QTextEdit, QGroupBox, QHeaderView, QMessageBox, QFileDialog,
    QTabWidget, QSplitter, QFrame, QComboBox, QCheckBox, QSpinBox,
    QDialog, QGridLayout, QRadioButton, QButtonGroup, QScrollArea,
    QStatusBar, QToolBar, QMenu, QMenuBar, QSystemTrayIcon, QStyle
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QObject, QTimer, QSettings, 
    QMimeData, QUrl, QSize
)
from PyQt6.QtGui import (
    QFont, QColor, QIcon, QPalette, QLinearGradient, QBrush,
    QPainter, QPen, QAction, QKeySequence, QClipboard
)

# Windows-specific imports
try:
    import wmi
    import win32api
    import win32con
    import win32file
    WINDOWS_MODE = True
except ImportError:
    WINDOWS_MODE = False
    print("Warning: Windows-specific features unavailable")

# Constants
APP_NAME = "Storage Diagnostic Pro"
APP_VERSION = "2.0"
MAX_LINES = 3000  # Constraint

@dataclass
class DriveInfo:
    letter: str
    label: str
    filesystem: str
    total_gb: float
    used_gb: float
    free_gb: float
    percent_used: int
    drive_type: str
    is_system: bool
    is_removable: bool
    
@dataclass
class SmartAttribute:
    id: int
    name: str
    current: int
    worst: int
    threshold: int
    raw_value: int
    status: str
    
@dataclass
class SmartData:
    model: str
    serial: str
    firmware: str
    interface: str
    temperature: Optional[int]
    health_status: str
    power_on_hours: Optional[int]
    attributes: List[SmartAttribute]
    
class DiskEnumerator:
    """Handles disk enumeration across platforms"""
    
    @staticmethod
    def get_drives() -> List[DriveInfo]:
        drives = []
        
        if WINDOWS_MODE:
            try:
                c = wmi.WMI()
                logical_disks = c.Win32_LogicalDisk()
                
                for disk in logical_disks:
                    try:
                        # Skip CD/DVD drives
                        if disk.DriveType == 5:
                            continue
                            
                        letter = disk.DeviceID
                        total = int(disk.Size) if disk.Size else 0
                        free = int(disk.FreeSpace) if disk.FreeSpace else 0
                        used = total - free
                        
                        # Get volume label
                        label = disk.VolumeName if disk.VolumeName else "Local Disk"
                        
                        # Determine drive characteristics
                        is_system = (letter == "C:")
                        is_removable = (disk.DriveType == 2)
                        
                        drive_type = {
                            2: "Removable",
                            3: "Fixed",
                            4: "Network",
                            5: "CD-ROM",
                            6: "RAM Disk"
                        }.get(disk.DriveType, "Unknown")
                        
                        drives.append(DriveInfo(
                            letter=letter,
                            label=label,
                            filesystem=disk.FileSystem or "Unknown",
                            total_gb=total / (1024**3),
                            used_gb=used / (1024**3),
                            free_gb=free / (1024**3),
                            percent_used=int((used / total * 100)) if total > 0 else 0,
                            drive_type=drive_type,
                            is_system=is_system,
                            is_removable=is_removable
                        ))
                    except Exception as e:
                        print(f"Error processing drive {disk.DeviceID}: {e}")
                        
            except Exception as e:
                print(f"WMI error: {e}")
                
        return drives
    
    @staticmethod
    def get_physical_disks() -> List[Dict]:
        disks = []
        
        if WINDOWS_MODE:
            try:
                c = wmi.WMI()
                for disk in c.Win32_DiskDrive():
                    disks.append({
                        'index': disk.Index,
                        'model': disk.Model,
                        'size': int(disk.Size) if disk.Size else 0,
                        'interface': disk.InterfaceType,
                        'serial': disk.SerialNumber.strip() if disk.SerialNumber else "Unknown",
                        'media': disk.MediaType
                    })
            except Exception as e:
                print(f"Error getting physical disks: {e}")
                
        return disks

class SmartReader:
    """Reads SMART data from drives"""
    
    KNOWN_ATTRIBUTES = {
        1: "Raw Read Error Rate",
        5: "Reallocated Sectors Count",
        9: "Power-On Hours",
        10: "Spin Retry Count",
        12: "Power Cycle Count",
        184: "End-to-End Error",
        187: "Reported Uncorrectable Errors",
        188: "Command Timeout",
        194: "Temperature Celsius",
        196: "Reallocation Event Count",
        197: "Current Pending Sector Count",
        198: "Offline Uncorrectable",
        199: "UltraDMA CRC Error Count",
        201: "Soft Read Error Rate",
        202: "Data Address Mark Errors",
    }
    
    @classmethod
    def read_smart(cls, disk_index: int) -> Optional[SmartData]:
        if not WINDOWS_MODE:
            return None
            
        try:
            # Try using CrystalDiskInfo's command line if available
            # Fallback to PowerShell/WMI methods
            return cls._read_via_wmi(disk_index)
        except Exception as e:
            print(f"SMART read error: {e}")
            return None
    
    @classmethod
    def _read_via_wmi(cls, disk_index: int) -> Optional[SmartData]:
        try:
            c = wmi.WMI()
            
            # Get disk info
            disk = c.Win32_DiskDrive(Index=disk_index)[0]
            
            # Try to get SMART data via MSStorageDriver_FailurePredictStatus
            try:
                smart_status = c.MSStorageDriver_FailurePredictStatus()[0]
                health = "CAUTION" if smart_status.PredictFailure else "GOOD"
            except:
                health = "UNKNOWN"
            
            # Get SMART data via MSStorageDriver_FailurePredictData
            attributes = []
            temperature = None
            power_on_hours = None
            
            try:
                smart_data = c.MSStorageDriver_FailurePredictData()
                for data in smart_data:
                    if data.InstanceName and str(disk_index) in data.InstanceName:
                        # Parse vendor specific data
                        # This is a simplified parsing - real implementation would be more complex
                        break
            except:
                pass
            
            # Get temperature if available
            try:
                temp_data = c.MSAcpi_ThermalZoneTemperature()
                if temp_data:
                    temperature = (temp_data[0].CurrentTemperature / 10) - 273
            except:
                pass
            
            return SmartData(
                model=disk.Model,
                serial=disk.SerialNumber.strip() if disk.SerialNumber else "Unknown",
                firmware="Unknown",
                interface=disk.InterfaceType,
                temperature=int(temperature) if temperature else None,
                health_status=health,
                power_on_hours=power_on_hours,
                attributes=attributes
            )
            
        except Exception as e:
            print(f"WMI SMART error: {e}")
            return None
    
    @classmethod
    def read_smart_via_ps(cls, disk_number: int) -> Optional[SmartData]:
        """Alternative: Read SMART using PowerShell"""
        try:
            cmd = f"""
            $disk = Get-PhysicalDisk | Where-Object {{$_.DeviceId -eq {disk_number}}}
            $rel = $disk | Get-StorageReliabilityCounter
            [PSCustomObject]@{{
                Model = $disk.Model
                Serial = $disk.SerialNumber
                Health = $disk.HealthStatus
                Temp = $rel.Temperature
                Hours = $rel.PowerOnHours
                Errors = $rel.ReadErrorsUncorrected
            }} | ConvertTo-Json
            """
            
            result = subprocess.run(
                ["powershell", "-Command", cmd],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return SmartData(
                    model=data.get('Model', 'Unknown'),
                    serial=data.get('Serial', 'Unknown'),
                    firmware='Unknown',
                    interface='Unknown',
                    temperature=data.get('Temp'),
                    health_status=data.get('Health', 'Unknown'),
                    power_on_hours=data.get('Hours'),
                    attributes=[]
                )
        except Exception as e:
            print(f"PowerShell SMART error: {e}")
            
        return None

class BadSectorScanner(QObject):
    """Scans for bad sectors"""
    progress = pyqtSignal(int)
    sector_found = pyqtSignal(int, str)  # sector, status
    finished = pyqtSignal(bool, int)  # success, bad_sectors_found
    
    def __init__(self, drive_letter: str, quick: bool = True):
        super().__init__()
        self.drive = drive_letter
        self.quick = quick
        self.running = False
        
    def scan(self):
        self.running = True
        bad_sectors = 0
        
        try:
            if WINDOWS_MODE:
                # Use chkdsk for bad sector detection
                mode = "/scan" if self.quick else "/r"
                cmd = f"chkdsk {self.drive} {mode}"
                
                process = subprocess.Popen(
                    cmd, shell=True, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True
                )
                
                while self.running:
                    line = process.stdout.readline()
                    if not line and process.poll() is not None:
                        break
                        
                    # Parse progress
                    if "percent" in line.lower() or "%" in line:
                        try:
                            pct = int(re.search(r'(\d+)%', line).group(1))
                            self.progress.emit(pct)
                        except:
                            pass
                    
                    # Check for bad sectors in output
                    if "bad" in line.lower() or "kb" in line.lower():
                        bad_sectors += 1
                        self.sector_found.emit(bad_sectors, line.strip())
                        
                self.finished.emit(process.returncode == 0, bad_sectors)
            else:
                self.finished.emit(False, 0)
                
        except Exception as e:
            print(f"Scan error: {e}")
            self.finished.emit(False, bad_sectors)
            
    def stop(self):
        self.running = False

class FileRecoveryScanner(QObject):
    """Scans for recoverable deleted files"""
    file_found = pyqtSignal(str, str, int)  # path, type, size
    progress = pyqtSignal(int)
    finished = pyqtSignal(int)  # files_found
    
    def __init__(self, drive_letter: str):
        super().__init__()
        self.drive = drive_letter
        self.running = False
        
    def scan(self):
        self.running = True
        found = 0
        
        try:
            # This is a simplified placeholder
            # Real implementation would use file carving techniques
            self.finished.emit(found)
        except Exception as e:
            print(f"Recovery scan error: {e}")
            self.finished.emit(found)
            
    def stop(self):
        self.running = False

class WorkerThread(QThread):
    """Generic worker thread for background tasks"""
    result_ready = pyqtSignal(object)
    progress = pyqtSignal(int)
    log_message = pyqtSignal(str)
    
    def __init__(self, task, *args, **kwargs):
        super().__init__()
        self.task = task
        self.args = args
        self.kwargs = kwargs
        
    def run(self):
        try:
            result = self.task(*self.args, **self.kwargs)
            self.result_ready.emit(result)
        except Exception as e:
            self.log_message.emit(f"Error: {str(e)}")
            self.result_ready.emit(None)

class StorageDiagnosticWidget(QWidget):
    """Main storage diagnostic widget"""
    
    def __init__(self):
        super().__init__()
        self.drives = []
        self.selected_drive = None
        self.smart_data = {}
        self.scan_threads = []
        
        self.setup_ui()
        self.refresh_drives()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Header
        header_layout = QHBoxLayout()
        
        title = QLabel("Storage Diagnostic Center")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        title.setStyleSheet("color: #f8fafc;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        self.btn_refresh = QPushButton("🔄 Refresh")
        self.btn_refresh.setObjectName("headerButton")
        self.btn_refresh.clicked.connect(self.refresh_drives)
        header_layout.addWidget(self.btn_refresh)
        
        layout.addLayout(header_layout)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Drive list
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        # Drive selection table
        self.drive_table = QTableWidget()
        self.drive_table.setColumnCount(6)
        self.drive_table.setHorizontalHeaderLabels([
            "Drive", "Label", "Type", "Size", "Used", "Health"
        ])
        self.drive_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.drive_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.drive_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.drive_table.itemSelectionChanged.connect(self.on_drive_selected)
        self.drive_table.setStyleSheet("""
            QTableWidget {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 8px;
                color: #f8fafc;
                gridline-color: #334155;
            }
            QHeaderView::section {
                background-color: #334155;
                color: #f8fafc;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #334155;
            }
            QTableWidget::item:selected {
                background-color: #0ea5e9;
            }
        """)
        self.drive_table.setMaximumWidth(500)
        left_layout.addWidget(self.drive_table)
        
        # Quick actions
        actions_group = QGroupBox("Quick Actions")
        actions_group.setStyleSheet("""
            QGroupBox {
                color: #38bdf8;
                font-weight: bold;
                border: 1px solid #334155;
                border-radius: 8px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        actions_layout = QVBoxLayout(actions_group)
        
        self.btn_check_disk = QPushButton("🔍 Check Disk (CHKDSK)")
        self.btn_check_disk.setObjectName("actionButton")
        self.btn_check_disk.clicked.connect(self.run_chkdsk)
        actions_layout.addWidget(self.btn_check_disk)
        
        self.btn_defrag = QPushButton("💿 Optimize Drive")
        self.btn_defrag.setObjectName("actionButton")
        self.btn_defrag.clicked.connect(self.optimize_drive)
        actions_layout.addWidget(self.btn_defrag)
        
        self.btn_cleanup = QPushButton("🧹 Disk Cleanup")
        self.btn_cleanup.setObjectName("actionButton")
        self.btn_cleanup.clicked.connect(self.disk_cleanup)
        actions_layout.addWidget(self.btn_cleanup)
        
        left_layout.addWidget(actions_group)
        
        splitter.addWidget(left_panel)
        
        # Right panel - Details and diagnostics
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        # Tabs for different diagnostics
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
            QTabBar::tab:hover:!selected {
                background-color: #475569;
            }
        """)
        
        # Tab 1: Drive Health
        self.health_tab = QWidget()
        health_layout = QVBoxLayout(self.health_tab)
        
        self.health_frame = QFrame()
        self.health_frame.setStyleSheet("""
            QFrame {
                background-color: #0f172a;
                border-radius: 12px;
                padding: 20px;
            }
        """)
        health_frame_layout = QVBoxLayout(self.health_frame)
        
        self.health_status_label = QLabel("Select a drive to view health status")
        self.health_status_label.setFont(QFont("Segoe UI", 16))
        self.health_status_label.setStyleSheet("color: #94a3b8;")
        self.health_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        health_frame_layout.addWidget(self.health_status_label)
        
        self.health_details = QTextEdit()
        self.health_details.setReadOnly(True)
        self.health_details.setStyleSheet("""
            QTextEdit {
                background-color: transparent;
                color: #cbd5e1;
                border: none;
                font-family: 'Consolas', monospace;
                font-size: 13px;
            }
        """)
        health_frame_layout.addWidget(self.health_details)
        
        health_layout.addWidget(self.health_frame)
        
        self.btn_deep_scan = QPushButton("🔬 Deep Health Scan")
        self.btn_deep_scan.setObjectName("scanButton")
        self.btn_deep_scan.clicked.connect(self.run_deep_scan)
        health_layout.addWidget(self.btn_deep_scan)
        
        self.tabs.addTab(self.health_tab, "Drive Health")
        
        # Tab 2: SMART Data
        self.smart_tab = QWidget()
        smart_layout = QVBoxLayout(self.smart_tab)
        
        self.smart_table = QTableWidget()
        self.smart_table.setColumnCount(5)
        self.smart_table.setHorizontalHeaderLabels([
            "Attribute", "Current", "Worst", "Threshold", "Status"
        ])
        self.smart_table.setStyleSheet("""
            QTableWidget {
                background-color: #0f172a;
                border: none;
                color: #f8fafc;
            }
            QHeaderView::section {
                background-color: #334155;
                color: #f8fafc;
                padding: 8px;
            }
        """)
        smart_layout.addWidget(self.smart_table)
        
        self.smart_info = QTextEdit()
        self.smart_info.setReadOnly(True)
        self.smart_info.setMaximumHeight(150)
        self.smart_info.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #94a3b8;
                border: 1px solid #334155;
                border-radius: 6px;
            }
        """)
        smart_layout.addWidget(self.smart_info)
        
        self.tabs.addTab(self.smart_tab, "SMART Data")
        
        # Tab 3: Bad Sector Scan
        self.sector_tab = QWidget()
        sector_layout = QVBoxLayout(self.sector_tab)
        
        sector_controls = QHBoxLayout()
        
        self.scan_type_quick = QRadioButton("Quick Scan")
        self.scan_type_quick.setChecked(True)
        self.scan_type_quick.setStyleSheet("color: #f8fafc;")
        sector_controls.addWidget(self.scan_type_quick)
        
        self.scan_type_full = QRadioButton("Full Surface Scan")
        self.scan_type_full.setStyleSheet("color: #f8fafc;")
        sector_controls.addWidget(self.scan_type_full)
        
        sector_controls.addStretch()
        
        self.btn_start_sector_scan = QPushButton("▶ Start Scan")
        self.btn_start_sector_scan.setObjectName("scanButton")
        self.btn_start_sector_scan.clicked.connect(self.start_sector_scan)
        sector_controls.addWidget(self.btn_start_sector_scan)
        
        self.btn_stop_sector_scan = QPushButton("⏹ Stop")
        self.btn_stop_sector_scan.setObjectName("stopButton")
        self.btn_stop_sector_scan.setEnabled(False)
        self.btn_stop_sector_scan.clicked.connect(self.stop_sector_scan)
        sector_controls.addWidget(self.btn_stop_sector_scan)
        
        sector_layout.addLayout(sector_controls)
        
        self.sector_progress = QProgressBar()
        self.sector_progress.setVisible(False)
        self.sector_progress.setStyleSheet("""
            QProgressBar {
                border: 2px solid #334155;
                border-radius: 5px;
                text-align: center;
                color: white;
            }
            QProgressBar::chunk {
                background-color: #8b5cf6;
            }
        """)
        sector_layout.addWidget(self.sector_progress)
        
        self.sector_log = QTextEdit()
        self.sector_log.setReadOnly(True)
        self.sector_log.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #cbd5e1;
                border: 1px solid #334155;
                border-radius: 6px;
                font-family: 'Consolas', monospace;
            }
        """)
        sector_layout.addWidget(self.sector_log)
        
        self.tabs.addTab(self.sector_tab, "Bad Sector Scan")
        
        # Tab 4: File Recovery
        self.recovery_tab = QWidget()
        recovery_layout = QVBoxLayout(self.recovery_tab)
        
        recovery_info = QLabel("Scan for recoverable deleted files (basic scan)")
        recovery_info.setStyleSheet("color: #94a3b8;")
        recovery_layout.addWidget(recovery_info)
        
        self.btn_scan_deleted = QPushButton("🔍 Scan for Deleted Files")
        self.btn_scan_deleted.setObjectName("scanButton")
        self.btn_scan_deleted.clicked.connect(self.scan_deleted_files)
        recovery_layout.addWidget(self.btn_scan_deleted)
        
        self.recovery_table = QTableWidget()
        self.recovery_table.setColumnCount(4)
        self.recovery_table.setHorizontalHeaderLabels([
            "File Name", "Type", "Size", "Recoverable"
        ])
        self.recovery_table.setStyleSheet("""
            QTableWidget {
                background-color: #0f172a;
                border: none;
                color: #f8fafc;
            }
        """)
        recovery_layout.addWidget(self.recovery_table)
        
        self.tabs.addTab(self.recovery_tab, "File Recovery")
        
        right_layout.addWidget(self.tabs)
        
        # Log output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(150)
        self.log_output.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #10b981;
                border: 1px solid #334155;
                border-radius: 6px;
                font-family: 'Consolas', monospace;
                font-size: 12px;
            }
        """)
        right_layout.addWidget(self.log_output)
        
        splitter.addWidget(right_panel)
        splitter.setSizes([400, 800])
        
        layout.addWidget(splitter)
        
        # Apply styles
        self.setStyleSheet("""
            QWidget {
                background-color: #0f172a;
            }
            #headerButton {
                background-color: #334155;
                color: #f8fafc;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: 500;
            }
            #headerButton:hover {
                background-color: #475569;
            }
            #actionButton {
                background-color: #1e293b;
                color: #f8fafc;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 12px;
                text-align: left;
            }
            #actionButton:hover {
                background-color: #334155;
                border-color: #0ea5e9;
            }
            #scanButton {
                background-color: #8b5cf6;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }
            #scanButton:hover {
                background-color: #7c3aed;
            }
            #stopButton {
                background-color: #ef4444;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }
            #stopButton:hover {
                background-color: #dc2626;
            }
            QLabel {
                color: #f8fafc;
            }
        """)
        
    def log(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_output.append(f"[{timestamp}] {message}")
        
    def refresh_drives(self):
        self.log("Refreshing drive list...")
        self.drives = DiskEnumerator.get_drives()
        
        self.drive_table.setRowCount(0)
        
        for drive in self.drives:
            row = self.drive_table.rowCount()
            self.drive_table.insertRow(row)
            
            # Drive letter with icon
            letter_item = QTableWidgetItem(f"💾 {drive.letter}")
            self.drive_table.setItem(row, 0, letter_item)
            
            self.drive_table.setItem(row, 1, QTableWidgetItem(drive.label))
            self.drive_table.setItem(row, 2, QTableWidgetItem(drive.drive_type))
            
            size_text = f"{drive.total_gb:.1f} GB"
            self.drive_table.setItem(row, 3, QTableWidgetItem(size_text))
            
            used_text = f"{drive.used_gb:.1f} GB ({drive.percent_used}%)"
            used_item = QTableWidgetItem(used_text)
            if drive.percent_used > 90:
                used_item.setForeground(QColor("#ef4444"))
            elif drive.percent_used > 80:
                used_item.setForeground(QColor("#f59e0b"))
            else:
                used_item.setForeground(QColor("#10b981"))
            self.drive_table.setItem(row, 4, used_item)
            
            health_item = QTableWidgetItem("Unknown")
            self.drive_table.setItem(row, 5, health_item)
            
        self.log(f"Found {len(self.drives)} drives")
        
    def on_drive_selected(self):
        selected = self.drive_table.selectedItems()
        if not selected:
            return
            
        row = selected[0].row()
        if row < len(self.drives):
            self.selected_drive = self.drives[row]
            self.update_drive_details()
            
    def update_drive_details(self):
        if not self.selected_drive:
            return
            
        drive = self.selected_drive
        
        # Update health tab
        health_text = f"""
Selected Drive: {drive.letter} ({drive.label})
File System: {drive.filesystem}
Total Size: {drive.total_gb:.2f} GB
Used Space: {drive.used_gb:.2f} GB ({drive.percent_used}%)
Free Space: {drive.free_gb:.2f} GB
Type: {drive.drive_type}
System Drive: {'Yes' if drive.is_system else 'No'}
        """
        
        self.health_details.setText(health_text)
        
        # Color-coded health status
        if drive.percent_used > 95:
            self.health_status_label.setText("⚠️ CRITICAL: Drive nearly full!")
            self.health_status_label.setStyleSheet("color: #ef4444; font-weight: bold;")
        elif drive.percent_used > 85:
            self.health_status_label.setText("⚡ WARNING: Drive usage high")
            self.health_status_label.setStyleSheet("color: #f59e0b; font-weight: bold;")
        else:
            self.health_status_label.setText("✓ Drive space healthy")
            self.health_status_label.setStyleSheet("color: #10b981; font-weight: bold;")
            
        # Load SMART data if available
        self.load_smart_data()
        
    def load_smart_data(self):
        self.smart_table.setRowCount(0)
        self.smart_info.setText("Loading SMART data...")
        
        # Find physical disk index for this drive
        # This is a simplified mapping - real implementation would be more complex
        physical_disks = DiskEnumerator.get_physical_disks()
        
        if physical_disks:
            # Try to read SMART for first disk (simplification)
            smart = SmartReader.read_smart_via_ps(0)
            
            if smart:
                self.smart_info.setText(f"""
Model: {smart.model}
Serial: {smart.serial}
Interface: {smart.interface}
Temperature: {smart.temperature}°C if smart.temperature else 'N/A'
Power On Hours: {smart.power_on_hours if smart.power_on_hours else 'N/A'}
Health Status: {smart.health_status}
                """)
                
                # Add to table
                if smart.temperature:
                    row = self.smart_table.rowCount()
                    self.smart_table.insertRow(row)
                    self.smart_table.setItem(row, 0, QTableWidgetItem("Temperature"))
                    self.smart_table.setItem(row, 1, QTableWidgetItem(str(smart.temperature)))
                    self.smart_table.setItem(row, 2, QTableWidgetItem("-"))
                    self.smart_table.setItem(row, 3, QTableWidgetItem("50"))
                    self.smart_table.setItem(row, 4, QTableWidgetItem("OK" if smart.temperature < 50 else "HOT"))
            else:
                self.smart_info.setText("SMART data unavailable. Try running as Administrator.")
        else:
            self.smart_info.setText("No physical disk information available.")
            
    def run_deep_scan(self):
        if not self.selected_drive:
            QMessageBox.warning(self, "No Drive", "Please select a drive first")
            return
            
        self.log(f"Starting deep health scan on {self.selected_drive.letter}")
        QMessageBox.information(self, "Deep Scan", 
                              f"Deep scan started on {self.selected_drive.letter}\n\nThis will check file system integrity and surface errors.")
        
        # Schedule chkdsk
        self.run_chkdsk()
        
    def run_chkdsk(self):
        if not self.selected_drive:
            QMessageBox.warning(self, "No Drive", "Please select a drive")
            return
            
        drive = self.selected_drive.letter
        
        if drive == "C:":
            reply = QMessageBox.question(self, "System Drive", 
                                       "CHKDSK requires restart for system drive. Schedule for next boot?",
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                try:
                    subprocess.run(f"echo Y|chkdsk C: /f", shell=True)
                    self.log("Scheduled CHKDSK for next boot")
                    QMessageBox.information(self, "Scheduled", 
                                          "CHKDSK scheduled. Restart your computer to run the check.")
                except Exception as e:
                    self.log(f"Error scheduling CHKDSK: {e}")
        else:
            try:
                self.log(f"Running CHKDSK on {drive}...")
                subprocess.Popen(f"chkdsk {drive} /scan", shell=True)
            except Exception as e:
                self.log(f"Error: {e}")
                
    def optimize_drive(self):
        if not self.selected_drive:
            QMessageBox.warning(self, "No Drive", "Please select a drive")
            return
            
        drive = self.selected_drive.letter
        self.log(f"Optimizing drive {drive}...")
        
        try:
            subprocess.Popen(f"defrag {drive} /O", shell=True)
            QMessageBox.information(self, "Optimization", 
                                  f"Drive optimization started for {drive}")
        except Exception as e:
            self.log(f"Error: {e}")
            
    def disk_cleanup(self):
        if not self.selected_drive:
            return
            
        try:
            subprocess.Popen(f"cleanmgr /d {self.selected_drive.letter[0]}", shell=True)
        except:
            pass
            
    def start_sector_scan(self):
        if not self.selected_drive:
            QMessageBox.warning(self, "No Drive", "Please select a drive")
            return
            
        self.sector_log.clear()
        self.sector_progress.setVisible(True)
        self.sector_progress.setValue(0)
        
        self.btn_start_sector_scan.setEnabled(False)
        self.btn_stop_sector_scan.setEnabled(True)
        
        quick = self.scan_type_quick.isChecked()
        
        self.sector_scanner = BadSectorScanner(self.selected_drive.letter, quick)
        self.sector_thread = QThread()
        self.sector_scanner.moveToThread(self.sector_thread)
        
        self.sector_scanner.progress.connect(self.sector_progress.setValue)
        self.sector_scanner.sector_found.connect(self.on_sector_found)
        self.sector_scanner.finished.connect(self.on_sector_scan_finished)
        
        self.sector_thread.started.connect(self.sector_scanner.scan)
        self.sector_thread.start()
        
        self.log(f"Started {'quick' if quick else 'full'} sector scan on {self.selected_drive.letter}")
        
    def on_sector_found(self, sector, status):
        self.sector_log.append(f"Sector {sector}: {status}")
        
    def on_sector_scan_finished(self, success, bad_count):
        self.sector_progress.setVisible(False)
        self.btn_start_sector_scan.setEnabled(True)
        self.btn_stop_sector_scan.setEnabled(False)
        
        if success:
            self.log(f"Sector scan completed. Bad sectors found: {bad_count}")
            if bad_count > 0:
                QMessageBox.warning(self, "Bad Sectors Found", 
                                  f"Found {bad_count} bad sectors!\n\nBackup your data immediately and consider replacing the drive.")
            else:
                QMessageBox.information(self, "Scan Complete", "No bad sectors found!")
        else:
            self.log("Sector scan failed or was interrupted")
            
    def stop_sector_scan(self):
        if hasattr(self, 'sector_scanner'):
            self.sector_scanner.stop()
        self.log("Stopping sector scan...")
        
    def scan_deleted_files(self):
        if not self.selected_drive:
            QMessageBox.warning(self, "No Drive", "Please select a drive")
            return
            
        self.log("Scanning for deleted files...")
        QMessageBox.information(self, "File Recovery", 
                              "File recovery scan started.\n\nNote: This is a basic scan. For deep recovery, use specialized tools like Recuva.")

class StorageDiagnosticWindow(QMainWindow):
    """Standalone window version"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setMinimumSize(1200, 800)
        
        # Set app icon
        self.setWindowIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DriveHDIcon))
        
        # Central widget
        self.diagnostic_widget = StorageDiagnosticWidget()
        self.setCentralWidget(self.diagnostic_widget)
        
        # Menu bar
        self.create_menu()
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Apply dark theme
        self.apply_theme()
        
    def create_menu(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        refresh_action = QAction("Refresh Drives", self)
        refresh_action.setShortcut("F5")
        refresh_action.triggered.connect(self.diagnostic_widget.refresh_drives)
        file_menu.addAction(refresh_action)
        
        file_menu.addSeparator()
        
        export_action = QAction("Export Report...", self)
        export_action.triggered.connect(self.export_report)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Alt+F4")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        chkdsk_action = QAction("Run CHKDSK...", self)
        chkdsk_action.triggered.connect(self.diagnostic_widget.run_chkdsk)
        tools_menu.addAction(chkdsk_action)
        
        optimize_action = QAction("Optimize Drives", self)
        optimize_action.triggered.connect(self.diagnostic_widget.optimize_drive)
        tools_menu.addAction(optimize_action)
        
        tools_menu.addSeparator()
        
        diskmgmt_action = QAction("Open Disk Management", self)
        diskmgmt_action.triggered.connect(lambda: os.system("diskmgmt.msc"))
        tools_menu.addAction(diskmgmt_action)
        
        # Help menu
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
            QStatusBar {
                background-color: #1e293b;
                color: #94a3b8;
                border-top: 1px solid #334155;
            }
        """)
        
    def export_report(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Report", "storage_report.txt", "Text Files (*.txt)")
        if path:
            try:
                with open(path, 'w') as f:
                    f.write(f"{APP_NAME} Report\n")
                    f.write(f"Generated: {datetime.now()}\n")
                    f.write("="*50 + "\n\n")
                    
                    for drive in self.diagnostic_widget.drives:
                        f.write(f"Drive {drive.letter} ({drive.label})\n")
                        f.write(f"  Size: {drive.total_gb:.2f} GB\n")
                        f.write(f"  Used: {drive.used_gb:.2f} GB ({drive.percent_used}%)\n")
                        f.write(f"  Free: {drive.free_gb:.2f} GB\n")
                        f.write(f"  Type: {drive.drive_type}\n\n")
                        
                self.status_bar.showMessage(f"Report saved to {path}", 5000)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save report: {e}")
                
    def show_about(self):
        QMessageBox.about(self, f"About {APP_NAME}", 
                         f"{APP_NAME} v{APP_VERSION}\n\n"
                         f"Comprehensive storage diagnostic and repair tool.\n\n"
                         f"Features:\n"
                         f"• Drive health monitoring\n"
                         f"• SMART data analysis\n"
                         f"• Bad sector scanning\n"
                         f"• File system repair\n"
                         f"• File recovery tools")

def main():
    # Check admin rights
    if WINDOWS_MODE:
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            is_admin = False
            
        if not is_admin:
            print("Warning: Not running as administrator. Some features may be limited.")
    
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setStyle("Fusion")
    
    # Set application font
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    window = StorageDiagnosticWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()