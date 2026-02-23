# main.py - Application Entry Point (approx 150 lines)
import sys
import os
import ctypes
from pathlib import Path
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QStackedWidget, QPushButton, QLabel,
                             QFrame, QMessageBox, QProgressBar, QStatusBar)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QIcon, QColor, QPalette, QLinearGradient, QBrush

# Import widget classes from modules
from dashboard import DashboardWidget
from storage_diagnostic import StorageDiagnosticWidget
from driver_manager import DriverManagerWidget
from memory_test import MemoryTestWidget
from system_repair import SystemRepairWidget
from conflict_resolver import ConflictResolverWidget
from power_management import PowerManagementWidget
from event_analyzer import EventAnalyzerWidget
from bsod_analyzer import BSODAnalyzerWidget

# Check admin privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BSOD Rescue & Diagnostic Suite Pro")
        self.setMinimumSize(1400, 900)
        self.setup_ui()
        self.apply_modern_theme()
        
    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Sidebar navigation
        self.sidebar = self.create_sidebar()
        main_layout.addWidget(self.sidebar)
        
        # Main content area
        self.content_stack = QStackedWidget()
        self.content_stack.setObjectName("contentArea")
        
        # Initialize all modules
        self.dashboard = DashboardWidget()
        self.storage_diag = StorageDiagnosticWidget()
        self.driver_mgr = DriverManagerWidget()
        self.memory_test = MemoryTestWidget()
        self.system_repair = SystemRepairWidget()
        self.conflict_resolver = ConflictResolverWidget()
        self.power_mgmt = PowerManagementWidget()
        self.event_analyzer = EventAnalyzerWidget()
        self.bsod_analyzer = BSODAnalyzerWidget()
        
        # Add to stack
        self.content_stack.addWidget(self.dashboard)      # 0
        self.content_stack.addWidget(self.storage_diag)   # 1
        self.content_stack.addWidget(self.driver_mgr)     # 2
        self.content_stack.addWidget(self.memory_test)    # 3
        self.content_stack.addWidget(self.system_repair)  # 4
        self.content_stack.addWidget(self.conflict_resolver) # 5
        self.content_stack.addWidget(self.power_mgmt)     # 6
        self.content_stack.addWidget(self.event_analyzer) # 7
        self.content_stack.addWidget(self.bsod_analyzer)  # 8
        
        main_layout.addWidget(self.content_stack, stretch=1)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready - Administrator privileges active")
        
    def create_sidebar(self):
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(280)
        
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(15, 20, 15, 20)
        layout.setSpacing(10)
        
        # Logo/Title
        title = QLabel("BSOD RESCUE\nPRO")
        title.setObjectName("appTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        layout.addWidget(title)
        
        layout.addSpacing(30)
        
        # Navigation buttons
        nav_items = [
            ("🏠 Dashboard", 0),
            ("💾 Storage Diagnosis", 1),
            ("🔌 Driver Manager", 2),
            ("🧠 Memory Test", 3),
            ("🔧 System Repair", 4),
            ("⚡ Conflict Resolver", 5),
            ("🔋 Power Management", 6),
            ("📊 Event Analyzer", 7),
            ("💥 BSOD Analyzer", 8),
        ]
        
        self.nav_buttons = []
        for text, index in nav_items:
            btn = QPushButton(text)
            btn.setObjectName("navButton")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, i=index: self.switch_page(i))
            layout.addWidget(btn)
            self.nav_buttons.append(btn)
        
        self.nav_buttons[0].setChecked(True)
        
        layout.addStretch()
        
        # System info footer
        footer = QLabel("v2.1.0 | Admin Mode")
        footer.setObjectName("footer")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(footer)
        
        return sidebar
    
    def switch_page(self, index):
        self.content_stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            btn.setChecked(i == index)
            
    def apply_modern_theme(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0f172a;
            }
            #sidebar {
                background-color: #1e293b;
                border-right: 1px solid #334155;
            }
            #appTitle {
                color: #38bdf8;
                padding: 10px;
            }
            #navButton {
                background-color: transparent;
                color: #94a3b8;
                border: none;
                border-radius: 8px;
                padding: 15px;
                text-align: left;
                font-size: 14px;
                font-weight: 500;
                margin: 2px 0;
            }
            #navButton:hover {
                background-color: #334155;
                color: #f1f5f9;
            }
            #navButton:checked {
                background-color: #0ea5e9;
                color: white;
            }
            #footer {
                color: #64748b;
                font-size: 11px;
                padding: 10px;
            }
            #contentArea {
                background-color: #0f172a;
            }
            QStatusBar {
                background-color: #1e293b;
                color: #94a3b8;
                border-top: 1px solid #334155;
            }
        """)

if __name__ == "__main__":
    # if not is_admin():
    #     ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    #     sys.exit()
    
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec())