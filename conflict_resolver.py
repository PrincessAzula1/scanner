# conflict_resolver.py - Software Conflict Detection (approx 350 lines)
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTableWidget, QTableWidgetItem,
                             QTextEdit, QGroupBox, QCheckBox, QMessageBox, QProgressBar)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor
import subprocess
import winreg
import os
from datetime import datetime

class ConflictScannerThread(QThread):
    conflicts_ready = pyqtSignal(list)
    progress = pyqtSignal(int)
    
    def run(self):
        conflicts = []
        
        # Check for problematic software
        problematic_software = [
            {'name': 'MacType', 'reason': 'Known to cause font rendering BSODs'},
            {'name': 'Razer Synapse', 'reason': 'Driver conflicts with power management'},
            {'name': 'Corsair iCUE', 'reason': 'USB driver conflicts'},
            {'name': 'MSI Afterburner', 'reason': 'GPU driver conflicts (outdated versions)'},
            {'name': 'Daemon Tools', 'reason': 'SCSI driver conflicts'},
            {'name': 'Alcohol 120%', 'reason': 'Storage driver conflicts'},
            {'name': 'Old Antivirus', 'reason': 'Kernel driver conflicts'},
        ]
        
        installed = self.get_installed_software()
        
        for i, software in enumerate(problematic_software):
            self.progress.emit(int((i / len(problematic_software)) * 50))
            
            matches = [s for s in installed if software['name'].lower() in s.lower()]
            if matches:
                conflicts.append({
                    'software': matches[0],
                    'reason': software['reason'],
                    'severity': 'HIGH',
                    'recommendation': 'Update to latest version or uninstall temporarily'
                })
                
        # Check startup items
        self.progress.emit(60)
        startup_items = self.get_startup_items()
        suspicious = [s for s in startup_items if any(x in s['name'].lower() for x in ['crack', 'patch', 'keygen', 'loader'])]
        
        for item in suspicious:
            conflicts.append({
                'software': item['name'],
                'reason': 'Suspicious startup item detected',
                'severity': 'CRITICAL',
                'recommendation': 'Remove immediately - potential malware'
            })
            
        # Check for multiple antivirus
        self.progress.emit(80)
        antivirus = [s for s in installed if any(x in s.lower() for x in ['antivirus', ' defender', 'security', 'mcafee', 'norton', 'avast', 'avg'])]
        if len(antivirus) > 1:
            conflicts.append({
                'software': ', '.join(antivirus[:2]) + ('...' if len(antivirus) > 2 else ''),
                'reason': 'Multiple antivirus programs detected',
                'severity': 'HIGH',
                'recommendation': 'Uninstall all but one to prevent conflicts'
            })
            
        self.progress.emit(100)
        self.conflicts_ready.emit(conflicts)
        
    def get_installed_software(self):
        software = []
        keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        ]
        
        for hkey, key_path in keys:
            try:
                key = winreg.OpenKey(hkey, key_path)
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                        software.append(name)
                        winreg.CloseKey(subkey)
                    except:
                        pass
                winreg.CloseKey(key)
            except:
                pass
                
        return software
    
    def get_startup_items(self):
        items = []
        keys = [
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        
        for hkey, key_path in keys:
            try:
                key = winreg.OpenKey(hkey, key_path)
                for i in range(winreg.QueryInfoKey(key)[1]):
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        items.append({'name': name, 'command': value})
                    except:
                        pass
                winreg.CloseKey(key)
            except:
                pass
                
        return items

class ConflictResolverWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        # Header
        header = QLabel("Software Conflict Resolver")
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: #f8fafc;")
        layout.addWidget(header)
        
        desc = QLabel("Detect software conflicts and problematic applications causing system instability")
        desc.setStyleSheet("color: #94a3b8; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.btn_scan = QPushButton("🔍 Scan for Conflicts")
        self.btn_scan.setObjectName("toolButton")
        self.btn_scan.clicked.connect(self.scan_conflicts)
        toolbar.addWidget(self.btn_scan)
        
        self.btn_clean_boot = QPushButton("🧹 Clean Boot Mode")
        self.btn_clean_boot.setObjectName("toolButton")
        self.btn_clean_boot.clicked.connect(self.configure_clean_boot)
        toolbar.addWidget(self.btn_clean_boot)
        
        toolbar.addStretch()
        
        self.btn_uninstall = QPushButton("🗑 Uninstall Selected")
        self.btn_uninstall.setObjectName("toolButtonWarning")
        self.btn_uninstall.clicked.connect(self.uninstall_selected)
        toolbar.addWidget(self.btn_uninstall)
        
        layout.addLayout(toolbar)
        
        # Conflicts table
        self.conflict_table = QTableWidget()
        self.conflict_table.setColumnCount(4)
        self.conflict_table.setHorizontalHeaderLabels(["Software", "Issue", "Severity", "Recommendation"])
        self.conflict_table.setStyleSheet("""
            QTableWidget {
                background-color: #1e293b;
                border: 1px solid #334155;
                color: #f8fafc;
                gridline-color: #334155;
            }
            QHeaderView::section {
                background-color: #334155;
                color: #f8fafc;
                padding: 10px;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 8px;
            }
        """)
        self.conflict_table.setMinimumHeight(300)
        layout.addWidget(self.conflict_table)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Details
        details_group = QGroupBox("Analysis Details")
        details_group.setStyleSheet("""
            QGroupBox {
                color: #38bdf8;
                font-weight: bold;
                border: 1px solid #334155;
                border-radius: 8px;
            }
        """)
        details_layout = QVBoxLayout(details_group)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #cbd5e1;
                border: none;
                font-family: 'Consolas', monospace;
            }
        """)
        details_layout.addWidget(self.details_text)
        
        layout.addWidget(details_group)
        
        # Tips
        tips_group = QGroupBox("Common Conflict Solutions")
        tips_group.setStyleSheet("""
            QGroupBox {
                color: #38bdf8;
                font-weight: bold;
                border: 1px solid #334155;
                border-radius: 8px;
            }
        """)
        tips_layout = QVBoxLayout(tips_group)
        
        tips = QLabel("""
• <b>Driver Conflicts:</b> Update all drivers to latest versions from manufacturer websites<br>
• <b>Antivirus Conflicts:</b> Never run more than one real-time antivirus<br>
• <b>Overlay Software:</b> Disable Steam, Discord, NVIDIA overlays temporarily<br>
• <b>RGB Software:</b> Update Corsair, Razer, MSI software - outdated versions cause BSODs<br>
• <b>Virtualization:</b> Disable Hyper-V if not needed, conflicts with some games/anticheat
        """)
        tips.setStyleSheet("color: #cbd5e1; line-height: 1.6;")
        tips.setWordWrap(True)
        tips_layout.addWidget(tips)
        
        layout.addWidget(tips_group)
        
        self.setStyleSheet("""
            #toolButton {
                background-color: #334155;
                color: #f8fafc;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
            }
            #toolButton:hover {
                background-color: #475569;
            }
            #toolButtonWarning {
                background-color: #dc2626;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
            }
            #toolButtonWarning:hover {
                background-color: #b91c1c;
            }
        """)
        
    def scan_conflicts(self):
        self.progress.setVisible(True)
        self.progress.setRange(0, 100)
        
        self.scan_thread = ConflictScannerThread()
        self.scan_thread.conflicts_ready.connect(self.on_conflicts_found)
        self.scan_thread.progress.connect(self.progress.setValue)
        self.scan_thread.start()
        
    def on_conflicts_found(self, conflicts):
        self.progress.setVisible(False)
        self.conflict_table.setRowCount(0)
        
        if not conflicts:
            self.details_text.setText("✓ No software conflicts detected. Your software configuration looks good!")
            return
            
        for conflict in conflicts:
            row = self.conflict_table.rowCount()
            self.conflict_table.insertRow(row)
            
            self.conflict_table.setItem(row, 0, QTableWidgetItem(conflict['software']))
            self.conflict_table.setItem(row, 1, QTableWidgetItem(conflict['reason']))
            
            sev_item = QTableWidgetItem(conflict['severity'])
            if conflict['severity'] == 'CRITICAL':
                sev_item.setForeground(QColor("#ef4444"))
                sev_item.setBackground(QColor("#450a0a"))
            elif conflict['severity'] == 'HIGH':
                sev_item.setForeground(QColor("#f59e0b"))
            else:
                sev_item.setForeground(QColor("#fbbf24"))
            self.conflict_table.setItem(row, 2, sev_item)
            
            self.conflict_table.setItem(row, 3, QTableWidgetItem(conflict['recommendation']))
            
        self.details_text.setText(f"⚠️ Found {len(conflicts)} potential conflict(s) that may cause system instability or BSODs.")
        
    def configure_clean_boot(self):
        reply = QMessageBox.question(self, "Clean Boot", 
                                   "Configure system for Clean Boot?\n\nThis will disable all non-Microsoft startup items and services.\n\nYou'll need to restart your computer.",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                # Use msconfig
                subprocess.Popen(["msconfig"])
                self.details_text.append("\n[Opened System Configuration. Select 'Selective startup' and uncheck 'Load startup items']")
            except:
                QMessageBox.critical(self, "Error", "Could not open System Configuration.")
                
    def uninstall_selected(self):
        selected = self.conflict_table.selectedItems()
        if not selected:
            QMessageBox.information(self, "Select Item", "Please select a software to uninstall")
            return
            
        software = self.conflict_table.item(selected[0].row(), 0).text()
        reply = QMessageBox.warning(self, "Confirm Uninstall", 
                                  f"Uninstall {software}?\n\nThis will open Control Panel Programs and Features.",
                                  QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                subprocess.Popen(["appwiz.cpl"], shell=True)
            except:
                pass