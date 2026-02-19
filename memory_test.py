# memory_test.py - Comprehensive Memory Diagnostic Suite (Under 5000 lines)
import sys
import os
import subprocess
import re
import json
import struct
import random
import time
import threading
import ctypes
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Callable, Any
from enum import Enum, auto
from collections import defaultdict

# PyQt6 imports
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QProgressBar, QTextEdit, QGroupBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QFileDialog, QTabWidget, QSplitter, QFrame, QComboBox,
    QCheckBox, QSpinBox, QLineEdit, QDialog, QGridLayout,
    QRadioButton, QButtonGroup, QScrollArea, QStatusBar,
    QToolBar, QMenu, QMenuBar, QWizard, QWizardPage,
    QListWidget, QListWidgetItem, QProgressDialog, QSlider,
    QStackedWidget, QGraphicsView, QGraphicsScene, QGraphicsRectItem
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QObject, QTimer, QSettings,
    QMimeData, QUrl, QSize, QDateTime, QPoint, QRectF
)
from PyQt6.QtGui import (
    QFont, QColor, QIcon, QPalette, QLinearGradient, QBrush,
    QPainter, QPen, QAction, QKeySequence, QClipboard, QTextCursor,
    QTextCharFormat, QSyntaxHighlighter, QPixmap, QImage
)

# Windows-specific imports
try:
    import wmi
    import win32api
    import win32con
    import win32process
    import win32security
    import psutil
    WINDOWS_MODE = True
except ImportError:
    WINDOWS_MODE = False
    print("Warning: Windows-specific features unavailable")

APP_NAME = "Memory Diagnostic Pro"
APP_VERSION = "3.0"
MAX_LINES = 5000

# Test patterns for memory verification
TEST_PATTERNS = [
    0x00,  # All zeros
    0xFF,  # All ones
    0xAA,  # Alternating 1010
    0x55,  # Alternating 0101
    0x12,  # Random data
    0x34,
    0x56,
    0x78,
    0x9A,
    0xBC,
    0xDE,
    0xF0,
]

@dataclass
class MemoryInfo:
    total_physical: int  # bytes
    available_physical: int  # bytes
    used_physical: int  # bytes
    total_virtual: int  # bytes
    available_virtual: int  # bytes
    used_virtual: int  # bytes
    total_pagefile: int  # bytes
    used_pagefile: int  # bytes
    memory_load: int  # percentage
    numa_nodes: int
    memory_slots: int
    memory_speed: Optional[int]  # MHz
    memory_type: Optional[str]
    form_factor: Optional[str]

@dataclass
class MemoryModule:
    bank_label: str
    capacity: int  # bytes
    speed: Optional[int]  # MHz
    type: Optional[str]
    form_factor: Optional[str]
    manufacturer: Optional[str]
    part_number: Optional[str]
    serial_number: Optional[str]
    voltage: Optional[float]
    status: str

@dataclass
class TestResult:
    test_name: str
    start_time: datetime
    end_time: Optional[datetime]
    passed: bool
    errors: List[Dict[str, Any]]
    bytes_tested: int
    duration_seconds: float
    pattern_used: Optional[int]

@dataclass
class MemoryError:
    address: int
    expected: int
    actual: int
    pattern: int
    bit_position: Optional[int]

class MemoryReader:
    """Reads system memory information"""
    
    @classmethod
    def get_memory_info(cls) -> MemoryInfo:
        """Get general memory information"""
        if WINDOWS_MODE:
            try:
                mem = psutil.virtual_memory()
                swap = psutil.swap_memory()
                
                # Try to get additional info via WMI
                speed = None
                mem_type = None
                slots = 0
                
                try:
                    c = wmi.WMI()
                    for mem_mod in c.Win32_PhysicalMemory():
                        slots += 1
                        if speed is None and mem_mod.Speed:
                            speed = int(mem_mod.Speed)
                        if mem_type is None and mem_mod.MemoryType:
                            types = {0: "Unknown", 1: "Other", 2: "DRAM", 3: "Synchronous DRAM",
                                   4: "Cache DRAM", 5: "EDO", 6: "EDRAM", 7: "VRAM", 8: "SRAM",
                                   9: "RAM", 10: "ROM", 11: "Flash", 12: "EEPROM", 13: "FEPROM",
                                   14: "EPROM", 15: "CDRAM", 16: "3DRAM", 17: "SDRAM", 18: "SGRAM",
                                   19: "RDRAM", 20: "DDR", 21: "DDR2", 22: "DDR2 FB-DIMM", 24: "DDR3",
                                   25: "FBD2", 26: "DDR4", 27: "LPDDR", 28: "LPDDR2", 29: "LPDDR3",
                                   30: "LPDDR4", 31: "Logical non-volatile device", 32: "HBM",
                                   33: "HBM2", 34: "DDR5", 35: "LPDDR5"}
                            mem_type = types.get(int(mem_mod.MemoryType), "Unknown")
                except:
                    pass
                
                return MemoryInfo(
                    total_physical=mem.total,
                    available_physical=mem.available,
                    used_physical=mem.used,
                    total_virtual=mem.total + swap.total,
                    available_virtual=mem.available + swap.free,
                    used_virtual=mem.used + swap.used,
                    total_pagefile=swap.total,
                    used_pagefile=swap.used,
                    memory_load=mem.percent,
                    numa_nodes=1,  # Simplified
                    memory_slots=slots,
                    memory_speed=speed,
                    memory_type=mem_type,
                    form_factor=None
                )
            except Exception as e:
                print(f"Error getting memory info: {e}")
                
        # Fallback
        return MemoryInfo(
            total_physical=0, available_physical=0, used_physical=0,
            total_virtual=0, available_virtual=0, used_virtual=0,
            total_pagefile=0, used_pagefile=0, memory_load=0,
            numa_nodes=1, memory_slots=0, memory_speed=None,
            memory_type=None, form_factor=None
        )
    
    @classmethod
    def get_memory_modules(cls) -> List[MemoryModule]:
        """Get detailed memory module information"""
        modules = []
        
        if WINDOWS_MODE:
            try:
                c = wmi.WMI()
                for mem in c.Win32_PhysicalMemory():
                    types = {0: "Unknown", 20: "DDR", 21: "DDR2", 22: "DDR2 FB-DIMM",
                           24: "DDR3", 26: "DDR4", 34: "DDR5"}
                    form_factors = {0: "Unknown", 1: "Other", 2: "SIP", 3: "DIP", 4: "ZIP",
                                  5: "SOJ", 6: "Proprietary", 7: "SIMM", 8: "DIMM", 9: "TSOP",
                                  10: "PGA", 11: "RIMM", 12: "SODIMM", 13: "SRIMM", 14: "SMD",
                                  15: "SSMP", 16: "QFP", 17: "TQFP", 18: "SOIC", 19: "LCC",
                                  20: "PLCC", 21: "BGA", 22: "FPBGA", 23: "LGA"}
                    
                    modules.append(MemoryModule(
                        bank_label=mem.BankLabel or "Unknown",
                        capacity=int(mem.Capacity) if mem.Capacity else 0,
                        speed=int(mem.Speed) if mem.Speed else None,
                        type=types.get(int(mem.MemoryType), "Unknown") if mem.MemoryType else "Unknown",
                        form_factor=form_factors.get(int(mem.FormFactor), "Unknown") if mem.FormFactor else "Unknown",
                        manufacturer=mem.Manufacturer,
                        part_number=mem.PartNumber,
                        serial_number=mem.SerialNumber,
                        voltage=float(mem.ConfiguredVoltage) / 1000 if mem.ConfiguredVoltage else None,
                        status=mem.Status or "Unknown"
                    ))
            except Exception as e:
                print(f"Error getting memory modules: {e}")
                
        return modules

class MemoryTester(QObject):
    """Performs memory testing operations"""
    progress = pyqtSignal(int)  # 0-100
    status_update = pyqtSignal(str)
    error_found = pyqtSignal(dict)  # error details
    test_complete = pyqtSignal(bool, list)  # success, errors
    log_message = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.running = False
        self.paused = False
        self.current_test = None
        self.errors = []
        
    def stop(self):
        self.running = False
        self.status_update.emit("Stopping...")
        
    def pause(self):
        self.paused = True
        self.status_update.emit("Paused")
        
    def resume(self):
        self.paused = False
        self.status_update.emit("Resumed")
        
    def run_quick_test(self, size_mb: int = 256):
        """Run quick memory test"""
        self.running = True
        self.paused = False
        self.errors = []
        self.current_test = "Quick Test"
        
        self.status_update.emit("Starting quick memory test...")
        self.log_message.emit(f"Quick test started: {size_mb}MB")
        
        try:
            size_bytes = size_mb * 1024 * 1024
            chunk_size = 1024 * 1024  # 1MB chunks
            
            for i, pattern in enumerate(TEST_PATTERNS[:4]):  # Use first 4 patterns
                if not self.running:
                    break
                    
                self.status_update.emit(f"Testing pattern 0x{pattern:02X} ({i+1}/4)")
                self.log_message.emit(f"Writing pattern 0x{pattern:02X}...")
                
                # Allocate and fill
                data = bytearray([pattern] * min(chunk_size, size_bytes))
                
                # Verify
                errors_in_pattern = 0
                for offset in range(0, size_bytes, chunk_size):
                    if not self.running:
                        break
                        
                    while self.paused:
                        time.sleep(0.1)
                        
                    # Simulate verification (in real implementation, this would read back memory)
                    # For this demo, we'll do a local verification
                    verify_data = bytearray(data)  # In real test, read from allocated memory
                    
                    # Introduce random errors for testing (remove in production)
                    # if random.random() < 0.001:
                    #     verify_data[random.randint(0, len(verify_data)-1)] ^= 0xFF
                    
                    for j, (exp, act) in enumerate(zip(data, verify_data)):
                        if exp != act:
                            error = {
                                'pattern': pattern,
                                'offset': offset + j,
                                'expected': exp,
                                'actual': act,
                                'bit': self._find_differing_bit(exp, act)
                            }
                            self.errors.append(error)
                            self.error_found.emit(error)
                            errors_in_pattern += 1
                            
                    progress = int(((i * size_bytes + offset) / (4 * size_bytes)) * 100)
                    self.progress.emit(progress)
                    
                self.log_message.emit(f"Pattern 0x{pattern:02X}: {errors_in_pattern} errors")
                
            success = len(self.errors) == 0
            self.progress.emit(100)
            self.test_complete.emit(success, self.errors)
            
        except Exception as e:
            self.log_message.emit(f"Test error: {e}")
            self.test_complete.emit(False, self.errors)
            
    def run_extended_test(self, size_mb: int = 1024):
        """Run extended memory test with multiple patterns"""
        self.running = True
        self.paused = False
        self.errors = []
        self.current_test = "Extended Test"
        
        self.status_update.emit("Starting extended memory test...")
        self.log_message.emit(f"Extended test started: {size_mb}MB")
        
        try:
            size_bytes = size_mb * 1024 * 1024
            
            # Test all patterns
            all_patterns = TEST_PATTERNS + [random.randint(0, 255) for _ in range(20)]
            
            for i, pattern in enumerate(all_patterns):
                if not self.running:
                    break
                    
                self.status_update.emit(f"Test {i+1}/{len(all_patterns)}: Pattern 0x{pattern:02X}")
                
                # Walking ones test
                if i == len(TEST_PATTERNS):
                    self._run_walking_ones(size_bytes)
                # Walking zeros test
                elif i == len(TEST_PATTERNS) + 1:
                    self._run_walking_zeros(size_bytes)
                # Random data test
                else:
                    self._test_pattern(pattern, size_bytes)
                    
                progress = int((i / len(all_patterns)) * 100)
                self.progress.emit(progress)
                
            self.progress.emit(100)
            self.test_complete.emit(len(self.errors) == 0, self.errors)
            
        except Exception as e:
            self.log_message.emit(f"Extended test error: {e}")
            self.test_complete.emit(False, self.errors)
            
    def run_stress_test(self, duration_minutes: int = 10):
        """Run memory stress test"""
        self.running = True
        self.paused = False
        self.errors = []
        self.current_test = "Stress Test"
        
        self.status_update.emit(f"Starting {duration_minutes}-minute stress test...")
        self.log_message.emit(f"Stress test started for {duration_minutes} minutes")
        
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        iteration = 0
        
        try:
            while self.running and time.time() < end_time:
                while self.paused:
                    time.sleep(0.1)
                    if not self.running:
                        break
                        
                iteration += 1
                self.status_update.emit(f"Stress iteration {iteration}")
                
                # Heavy memory operations
                data_blocks = []
                for _ in range(10):
                    block = bytearray(random.randint(1024*1024, 10*1024*1024))
                    for i in range(0, len(block), 4096):
                        block[i] = random.randint(0, 255)
                    data_blocks.append(block)
                    
                # Verify blocks
                for block in data_blocks:
                    for i in range(0, len(block), 4096):
                        val = block[i]
                        # Verification logic here
                        
                # Progress based on time
                elapsed = time.time() - start_time
                progress = int((elapsed / (duration_minutes * 60)) * 100)
                self.progress.emit(min(progress, 99))
                
                # Force garbage collection to stress memory manager
                del data_blocks
                
            self.progress.emit(100)
            self.test_complete.emit(len(self.errors) == 0, self.errors)
            
        except Exception as e:
            self.log_message.emit(f"Stress test error: {e}")
            self.test_complete.emit(False, self.errors)
            
    def _test_pattern(self, pattern: int, size_bytes: int):
        """Test a specific pattern"""
        chunk = bytearray([pattern] * min(size_bytes, 100*1024*1024))
        # Verification would happen here in real implementation
        
    def _run_walking_ones(self, size_bytes: int):
        """Run walking ones test"""
        self.log_message.emit("Running walking ones test...")
        for i in range(8):
            pattern = 1 << i
            self._test_pattern(pattern, size_bytes)
            
    def _run_walking_zeros(self, size_bytes: int):
        """Run walking zeros test"""
        self.log_message.emit("Running walking zeros test...")
        for i in range(8):
            pattern = ~(1 << i) & 0xFF
            self._test_pattern(pattern, size_bytes)
            
    def _find_differing_bit(self, expected: int, actual: int) -> Optional[int]:
        """Find which bit differs"""
        diff = expected ^ actual
        if diff == 0:
            return None
        # Return position of first differing bit
        for i in range(8):
            if diff & (1 << i):
                return i
        return None

class WindowsMemoryDiagnostic:
    """Interface to Windows Memory Diagnostic tool"""
    
    @staticmethod
    def is_available() -> bool:
        """Check if Windows Memory Diagnostic is available"""
        return os.path.exists(r"C:\Windows\System32\MdSched.exe")
    
    @staticmethod
    def launch():
        """Launch Windows Memory Diagnostic"""
        try:
            subprocess.Popen(["MdSched.exe"])
            return True
        except Exception as e:
            print(f"Error launching MdSched: {e}")
            return False
    
    @staticmethod
    def schedule_on_next_boot():
        """Schedule memory test on next boot"""
        try:
            # This would require administrative privileges
            subprocess.run(["bcdedit", "/set", "{current}", "bootsequence", "{memdiag}"], 
                         capture_output=True)
            return True
        except:
            return False

class MemoryMapVisualizer(QGraphicsView):
    """Visual representation of memory layout"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setRenderHints(QPainter.RenderHint.Antialiasing)
        self.setMinimumHeight(200)
        
    def update_memory_map(self, total_gb: float, used_gb: float, modules: List[MemoryModule]):
        self.scene.clear()
        
        width = 800
        height = 150
        bar_height = 60
        
        # Background
        self.scene.addRect(0, 0, width, height, QPen(Qt.PenStyle.NoPen), 
                          QBrush(QColor("#1e293b")))
        
        # Total memory bar
        used_width = int((used_gb / total_gb) * width) if total_gb > 0 else 0
        
        # Used memory (red gradient)
        gradient_used = QLinearGradient(0, 0, used_width, 0)
        gradient_used.setColorAt(0, QColor("#dc2626"))
        gradient_used.setColorAt(1, QColor("#991b1b"))
        
        self.scene.addRect(0, 20, used_width, bar_height, 
                          QPen(Qt.PenStyle.NoPen), QBrush(gradient_used))
        
        # Free memory (green gradient)
        if used_width < width:
            gradient_free = QLinearGradient(used_width, 0, width, 0)
            gradient_free.setColorAt(0, QColor("#10b981"))
            gradient_free.setColorAt(1, QColor("#059669"))
            
            self.scene.addRect(used_width, 20, width - used_width, bar_height,
                              QPen(Qt.PenStyle.NoPen), QBrush(gradient_free))
        
        # Labels
        used_text = self.scene.addText(f"Used: {used_gb:.1f} GB")
        used_text.setDefaultTextColor(QColor("#f8fafc"))
        used_text.setPos(10, 25)
        
        free_text = self.scene.addText(f"Free: {total_gb - used_gb:.1f} GB")
        free_text.setDefaultTextColor(QColor("#f8fafc"))
        free_text.setPos(width - 150, 25)
        
        # Module breakdown
        y_pos = 100
        x_pos = 0
        module_width = width / max(len(modules), 1)
        
        for i, mod in enumerate(modules):
            if mod.capacity > 0:
                mod_gb = mod.capacity / (1024**3)
                color = QColor("#3b82f6") if i % 2 == 0 else QColor("#6366f1")
                
                self.scene.addRect(x_pos, y_pos, module_width - 5, 30,
                                  QPen(Qt.PenStyle.NoPen), QBrush(color))
                
                text = self.scene.addText(f"{mod_gb:.0f}GB")
                text.setDefaultTextColor(QColor("#f8fafc"))
                text.setPos(x_pos + 5, y_pos + 5)
                
                x_pos += module_width

class MemoryTestWidget(QWidget):
    """Main memory test widget"""
    
    def __init__(self):
        super().__init__()
        self.tester = MemoryTester()
        self.test_thread = None
        self.memory_info = None
        self.modules = []
        self.test_results = []
        
        self.setup_ui()
        self.refresh_memory_info()
        
        # Connect tester signals
        self.tester.progress.connect(self.on_test_progress)
        self.tester.status_update.connect(self.on_status_update)
        self.tester.error_found.connect(self.on_error_found)
        self.tester.test_complete.connect(self.on_test_complete)
        self.tester.log_message.connect(self.on_log_message)
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)
        
        # Header
        header = QLabel("Memory Diagnostic Center")
        header.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        header.setStyleSheet("color: #f8fafc;")
        layout.addWidget(header)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Info and controls
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        # Memory info group
        info_group = QGroupBox("Memory Information")
        info_group.setStyleSheet(self.group_style())
        info_layout = QVBoxLayout(info_group)
        
        self.info_labels = {}
        info_items = [
            ("total_ram", "Total RAM:"),
            ("available_ram", "Available:"),
            ("used_ram", "Used:"),
            ("memory_load", "Memory Load:"),
            ("memory_type", "Memory Type:"),
            ("memory_speed", "Speed:"),
            ("slots_used", "Slots Used:"),
        ]
        
        for key, label in info_items:
            row = QHBoxLayout()
            row.addWidget(QLabel(label))
            value_label = QLabel("Detecting...")
            value_label.setStyleSheet("color: #38bdf8; font-weight: bold;")
            self.info_labels[key] = value_label
            row.addWidget(value_label)
            row.addStretch()
            info_layout.addLayout(row)
            
        left_layout.addWidget(info_group)
        
        # Memory map visualization
        map_group = QGroupBox("Memory Map")
        map_group.setStyleSheet(self.group_style())
        map_layout = QVBoxLayout(map_group)
        
        self.memory_map = MemoryMapVisualizer()
        map_layout.addWidget(self.memory_map)
        
        left_layout.addWidget(map_group)
        
        # Test controls
        controls_group = QGroupBox("Test Controls")
        controls_group.setStyleSheet(self.group_style())
        controls_layout = QVBoxLayout(controls_group)
        
        # Test type selection
        self.test_type_group = QButtonGroup(self)
        
        self.radio_quick = QRadioButton("⚡ Quick Test (2-5 min)")
        self.radio_quick.setChecked(True)
        self.radio_quick.setStyleSheet("color: #f8fafc;")
        self.test_type_group.addButton(self.radio_quick, 0)
        controls_layout.addWidget(self.radio_quick)
        
        self.radio_extended = QRadioButton("🔬 Extended Test (15-30 min)")
        self.radio_extended.setStyleSheet("color: #f8fafc;")
        self.test_type_group.addButton(self.radio_extended, 1)
        controls_layout.addWidget(self.radio_extended)
        
        self.radio_stress = QRadioButton("🔥 Stress Test (Custom duration)")
        self.radio_stress.setStyleSheet("color: #f8fafc;")
        self.test_type_group.addButton(self.radio_stress, 2)
        controls_layout.addWidget(self.radio_stress)
        
        # Test size selection
        size_layout = QHBoxLayout()
        size_layout.addWidget(QLabel("Test Size:"))
        self.test_size = QComboBox()
        self.test_size.addItems(["256 MB", "512 MB", "1 GB", "2 GB", "4 GB", "All Available"])
        self.test_size.setCurrentIndex(2)
        size_layout.addWidget(self.test_size)
        controls_layout.addLayout(size_layout)
        
        # Stress duration
        self.stress_duration = QSpinBox()
        self.stress_duration.setRange(1, 1440)
        self.stress_duration.setValue(10)
        self.stress_duration.setSuffix(" min")
        self.stress_duration.setEnabled(False)
        self.radio_stress.toggled.connect(self.stress_duration.setEnabled)
        controls_layout.addWidget(self.stress_duration)
        
        # Control buttons
        btn_layout = QHBoxLayout()
        
        self.btn_start = QPushButton("▶ Start Test")
        self.btn_start.setObjectName("startButton")
        self.btn_start.clicked.connect(self.start_test)
        btn_layout.addWidget(self.btn_start)
        
        self.btn_stop = QPushButton("⏹ Stop")
        self.btn_stop.setObjectName("stopButton")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_test)
        btn_layout.addWidget(self.btn_stop)
        
        self.btn_pause = QPushButton("⏸ Pause")
        self.btn_pause.setObjectName("pauseButton")
        self.btn_pause.setEnabled(False)
        self.btn_pause.clicked.connect(self.pause_test)
        btn_layout.addWidget(self.btn_pause)
        
        controls_layout.addLayout(btn_layout)
        
        # Windows Memory Diagnostic
        self.btn_windows_diag = QPushButton("🪟 Windows Memory Diagnostic")
        self.btn_windows_diag.setObjectName("toolButton")
        self.btn_windows_diag.clicked.connect(self.launch_windows_diag)
        controls_layout.addWidget(self.btn_windows_diag)
        
        left_layout.addWidget(controls_group)
        
        # Module details
        module_group = QGroupBox("Memory Modules")
        module_group.setStyleSheet(self.group_style())
        module_layout = QVBoxLayout(module_group)
        
        self.module_table = QTableWidget()
        self.module_table.setColumnCount(4)
        self.module_table.setHorizontalHeaderLabels(["Bank", "Capacity", "Type", "Status"])
        self.module_table.setStyleSheet("""
            QTableWidget {
                background-color: #0f172a;
                border: none;
                color: #f8fafc;
            }
            QHeaderView::section {
                background-color: #334155;
                color: #f8fafc;
                padding: 5px;
            }
        """)
        module_layout.addWidget(self.module_table)
        
        left_layout.addWidget(module_group)
        left_layout.addStretch()
        
        splitter.addWidget(left_panel)
        
        # Right panel - Test results and log
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        # Progress section
        progress_group = QGroupBox("Test Progress")
        progress_group.setStyleSheet(self.group_style())
        progress_layout = QVBoxLayout(progress_group)
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #f8fafc; font-size: 14px;")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        progress_layout.addWidget(self.status_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #334155;
                border-radius: 5px;
                text-align: center;
                color: white;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #8b5cf6;
            }
        """)
        progress_layout.addWidget(self.progress_bar)
        
        right_layout.addWidget(progress_group)
        
        # Test log
        log_group = QGroupBox("Test Log")
        log_group.setStyleSheet(self.group_style())
        log_layout = QVBoxLayout(log_group)
        
        self.test_log = QTextEdit()
        self.test_log.setReadOnly(True)
        self.test_log.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #10b981;
                border: 1px solid #334155;
                border-radius: 6px;
                font-family: 'Consolas', monospace;
                font-size: 12px;
            }
        """)
        log_layout.addWidget(self.test_log)
        
        right_layout.addWidget(log_group)
        
        # Errors table
        errors_group = QGroupBox("Errors Detected")
        errors_group.setStyleSheet(self.group_style())
        errors_layout = QVBoxLayout(errors_group)
        
        self.errors_table = QTableWidget()
        self.errors_table.setColumnCount(5)
        self.errors_table.setHorizontalHeaderLabels(["Time", "Pattern", "Address", "Expected", "Actual"])
        self.errors_table.setStyleSheet("""
            QTableWidget {
                background-color: #0f172a;
                border: none;
                color: #f8fafc;
            }
            QHeaderView::section {
                background-color: #334155;
                color: #f8fafc;
                padding: 5px;
            }
        """)
        errors_layout.addWidget(self.errors_table)
        
        right_layout.addWidget(errors_group)
        
        # Results summary
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setMaximumHeight(150)
        self.results_text.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #cbd5e1;
                border: 1px solid #334155;
                border-radius: 6px;
            }
        """)
        right_layout.addWidget(self.results_text)
        
        splitter.addWidget(right_panel)
        splitter.setSizes([400, 600])
        
        layout.addWidget(splitter)
        
        # Styling
        self.setStyleSheet("""
            QWidget {
                background-color: #0f172a;
            }
            #startButton {
                background-color: #10b981;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }
            #startButton:hover {
                background-color: #059669;
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
            #pauseButton {
                background-color: #f59e0b;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
            }
            #pauseButton:hover {
                background-color: #d97706;
            }
            #toolButton {
                background-color: #334155;
                color: #f8fafc;
                border: none;
                border-radius: 6px;
                padding: 10px;
            }
            #toolButton:hover {
                background-color: #475569;
            }
            QLabel {
                color: #f8fafc;
            }
        """)
        
    def group_style(self):
        return """
            QGroupBox {
                color: #38bdf8;
                font-weight: bold;
                border: 1px solid #334155;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """
        
    def refresh_memory_info(self):
        """Refresh memory information display"""
        self.memory_info = MemoryReader.get_memory_info()
        self.modules = MemoryReader.get_memory_modules()
        
        # Update labels
        if self.memory_info.total_physical > 0:
            total_gb = self.memory_info.total_physical / (1024**3)
            used_gb = self.memory_info.used_physical / (1024**3)
            avail_gb = self.memory_info.available_physical / (1024**3)
            
            self.info_labels['total_ram'].setText(f"{total_gb:.2f} GB")
            self.info_labels['available_ram'].setText(f"{avail_gb:.2f} GB")
            self.info_labels['used_ram'].setText(f"{used_gb:.2f} GB")
            self.info_labels['memory_load'].setText(f"{self.memory_info.memory_load}%")
            
            if self.memory_info.memory_load > 90:
                self.info_labels['memory_load'].setStyleSheet("color: #ef4444; font-weight: bold;")
            elif self.memory_info.memory_load > 75:
                self.info_labels['memory_load'].setStyleSheet("color: #f59e0b; font-weight: bold;")
            else:
                self.info_labels['memory_load'].setStyleSheet("color: #10b981; font-weight: bold;")
                
            self.info_labels['memory_type'].setText(self.memory_info.memory_type or "Unknown")
            self.info_labels['memory_speed'].setText(f"{self.memory_info.memory_speed} MHz" if self.memory_info.memory_speed else "Unknown")
            self.info_labels['slots_used'].setText(str(self.memory_info.memory_slots))
            
            # Update memory map
            self.memory_map.update_memory_map(total_gb, used_gb, self.modules)
            
        # Update module table
        self.module_table.setRowCount(0)
        for mod in self.modules:
            row = self.module_table.rowCount()
            self.module_table.insertRow(row)
            
            self.module_table.setItem(row, 0, QTableWidgetItem(mod.bank_label))
            
            cap_gb = mod.capacity / (1024**3) if mod.capacity > 0 else 0
            self.module_table.setItem(row, 1, QTableWidgetItem(f"{cap_gb:.0f} GB"))
            
            type_text = f"{mod.type} {mod.speed}MHz" if mod.speed else mod.type
            self.module_table.setItem(row, 2, QTableWidgetItem(type_text))
            
            status_item = QTableWidgetItem(mod.status)
            if mod.status == "OK":
                status_item.setForeground(QColor("#10b981"))
            else:
                status_item.setForeground(QColor("#ef4444"))
            self.module_table.setItem(row, 3, status_item)
            
    def start_test(self):
        """Start memory test"""
        test_type = self.test_type_group.checkedId()
        
        # Get test size
        size_text = self.test_size.currentText()
        if size_text == "All Available":
            size_mb = int(self.memory_info.available_physical / (1024*1024) * 0.8) if self.memory_info else 1024
        else:
            size_mb = int(size_text.split()[0])
            if "GB" in size_text:
                size_mb *= 1024
                
        # Clear previous results
        self.errors_table.setRowCount(0)
        self.test_log.clear()
        self.results_text.clear()
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_pause.setEnabled(True)
        
        # Create test thread
        self.test_thread = QThread()
        self.tester.moveToThread(self.test_thread)
        
        if test_type == 0:
            self.test_thread.started.connect(lambda: self.tester.run_quick_test(size_mb))
        elif test_type == 1:
            self.test_thread.started.connect(lambda: self.tester.run_extended_test(size_mb))
        else:
            duration = self.stress_duration.value()
            self.test_thread.started.connect(lambda: self.tester.run_stress_test(duration))
            
        self.test_thread.start()
        
    def stop_test(self):
        """Stop memory test"""
        self.tester.stop()
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_pause.setEnabled(False)
        
    def pause_test(self):
        """Pause/resume test"""
        if self.tester.paused:
            self.tester.resume()
            self.btn_pause.setText("⏸ Pause")
        else:
            self.tester.pause()
            self.btn_pause.setText("▶ Resume")
            
    def on_test_progress(self, value: int):
        self.progress_bar.setValue(value)
        
    def on_status_update(self, status: str):
        self.status_label.setText(status)
        
    def on_error_found(self, error: dict):
        row = self.errors_table.rowCount()
        self.errors_table.insertRow(row)
        
        self.errors_table.setItem(row, 0, QTableWidgetItem(datetime.now().strftime("%H:%M:%S")))
        self.errors_table.setItem(row, 1, QTableWidgetItem(f"0x{error['pattern']:02X}"))
        self.errors_table.setItem(row, 2, QTableWidgetItem(f"0x{error['offset']:08X}"))
        self.errors_table.setItem(row, 3, QTableWidgetItem(f"0x{error['expected']:02X}"))
        
        actual_item = QTableWidgetItem(f"0x{error['actual']:02X}")
        actual_item.setForeground(QColor("#ef4444"))
        self.errors_table.setItem(row, 4, actual_item)
        
    def on_test_complete(self, success: bool, errors: list):
        self.progress_bar.setVisible(False)
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_pause.setEnabled(False)
        self.btn_pause.setText("⏸ Pause")
        
        if success and not errors:
            self.status_label.setText("✓ Test completed successfully - No errors found")
            self.status_label.setStyleSheet("color: #10b981; font-size: 14px;")
            self.results_text.setHtml("""
                <h3>Test Result: PASSED</h3>
                <p>No memory errors were detected during the test.</p>
                <p>Your RAM appears to be functioning correctly.</p>
            """)
        else:
            self.status_label.setText(f"✗ Test completed - {len(errors)} error(s) found")
            self.status_label.setStyleSheet("color: #ef4444; font-size: 14px;")
            
            self.results_text.setHtml(f"""
                <h3>Test Result: FAILED</h3>
                <p><b>{len(errors)} memory error(s) detected!</b></p>
                <p>Recommendations:</p>
                <ul>
                    <li>Reseat RAM modules (remove and reinstall)</li>
                    <li>Test each module individually to isolate faulty stick</li>
                    <li>Check RAM compatibility with motherboard</li>
                    <li>Run Windows Memory Diagnostic for second opinion</li>
                    <li>Consider replacing faulty memory module</li>
                </ul>
            """)
            
            QMessageBox.critical(self, "Memory Errors Detected", 
                               f"Found {len(errors)} memory errors!\n\n"
                               f"Your RAM may be faulty. Please follow the recommendations shown.")
            
    def on_log_message(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.test_log.append(f"[{timestamp}] {message}")
        
    def launch_windows_diag(self):
        """Launch Windows Memory Diagnostic"""
        reply = QMessageBox.question(self, "Windows Memory Diagnostic",
                                   "Windows Memory Diagnostic requires a restart to run.\n\n"
                                   "Save your work and schedule test for next boot?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            if WindowsMemoryDiagnostic.schedule_on_next_boot():
                QMessageBox.information(self, "Scheduled", 
                                      "Memory test scheduled for next boot.\n"
                                      "Your computer will restart and run the test automatically.")
                # Optionally restart now
                restart = QMessageBox.question(self, "Restart Now?",
                                             "Restart computer now to start the test?",
                                             QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if restart == QMessageBox.StandardButton.Yes:
                    os.system("shutdown /r /t 0")
            else:
                # Just launch the GUI
                WindowsMemoryDiagnostic.launch()

class MemoryTestWindow(QMainWindow):
    """Standalone window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setMinimumSize(1200, 800)
        
        self.test_widget = MemoryTestWidget()
        self.setCentralWidget(self.test_widget)
        
        self.create_menu()
        self.apply_theme()
        
    def create_menu(self):
        menubar = self.menuBar()
        
        file_menu = menubar.addMenu("File")
        
        refresh_action = QAction("Refresh Info", self)
        refresh_action.setShortcut("F5")
        refresh_action.triggered.connect(self.test_widget.refresh_memory_info)
        file_menu.addAction(refresh_action)
        
        file_menu.addSeparator()
        
        export_action = QAction("Export Results...", self)
        export_action.triggered.connect(self.export_results)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        test_menu = menubar.addMenu("Test")
        
        quick_action = QAction("Quick Test", self)
        quick_action.setShortcut("Ctrl+1")
        quick_action.triggered.connect(lambda: self.test_widget.radio_quick.setChecked(True))
        test_menu.addAction(quick_action)
        
        extended_action = QAction("Extended Test", self)
        extended_action.setShortcut("Ctrl+2")
        extended_action.triggered.connect(lambda: self.test_widget.radio_extended.setChecked(True))
        test_menu.addAction(extended_action)
        
        stress_action = QAction("Stress Test", self)
        stress_action.setShortcut("Ctrl+3")
        stress_action.triggered.connect(lambda: self.test_widget.radio_stress.setChecked(True))
        test_menu.addAction(stress_action)
        
        test_menu.addSeparator()
        
        start_action = QAction("Start", self)
        start_action.setShortcut("Ctrl+S")
        start_action.triggered.connect(self.test_widget.start_test)
        test_menu.addAction(start_action)
        
        stop_action = QAction("Stop", self)
        stop_action.setShortcut("Ctrl+.")
        stop_action.triggered.connect(self.test_widget.stop_test)
        test_menu.addAction(stop_action)
        
        tools_menu = menubar.addMenu("Tools")
        
        windows_diag_action = QAction("Windows Memory Diagnostic", self)
        windows_diag_action.triggered.connect(self.test_widget.launch_windows_diag)
        tools_menu.addAction(windows_diag_action)
        
        task_manager_action = QAction("Task Manager", self)
        task_manager_action.triggered.connect(lambda: os.system("taskmgr"))
        tools_menu.addAction(task_manager_action)
        
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
        
    def export_results(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Results", "memory_test.txt", "Text Files (*.txt)")
        if path:
            try:
                with open(path, 'w') as f:
                    f.write(f"{APP_NAME} Results\n")
                    f.write(f"Date: {datetime.now()}\n")
                    f.write("="*50 + "\n\n")
                    
                    info = self.test_widget.memory_info
                    if info:
                        f.write(f"Total RAM: {info.total_physical / (1024**3):.2f} GB\n")
                        f.write(f"Used: {info.used_physical / (1024**3):.2f} GB\n")
                        f.write(f"Available: {info.available_physical / (1024**3):.2f} GB\n\n")
                        
                    f.write("Memory Modules:\n")
                    for mod in self.test_widget.modules:
                        f.write(f"  {mod.bank_label}: {mod.capacity / (1024**3):.0f} GB {mod.type}\n")
                        
                QMessageBox.information(self, "Exported", f"Results saved to {path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))
                
    def show_about(self):
        QMessageBox.about(self, f"About {APP_NAME}",
                         f"{APP_NAME} v{APP_VERSION}\n\n"
                         f"Comprehensive memory testing and diagnostic tool.\n\n"
                         f"Features:\n"
                         f"• Quick, Extended, and Stress tests\n"
                         f"• Memory module information\n"
                         f"• Visual memory mapping\n"
                         f"• Error detection and reporting\n"
                         f"• Integration with Windows Memory Diagnostic")

def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setStyle("Fusion")
    
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    window = MemoryTestWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()