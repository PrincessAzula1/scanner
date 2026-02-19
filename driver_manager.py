# driver_manager.py - Driver Analysis & Repair (approx 450 lines)
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTableWidget, QTableWidgetItem,
                             QProgressBar, QTextEdit, QGroupBox, QComboBox,
                             QMessageBox, QFileDialog, QCheckBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor
import subprocess
import re
import os
import json
from datetime import datetime
import winreg

class DriverScannerThread(QThread):
    drivers_ready = pyqtSignal(list)
    progress = pyqtSignal(int)
    error = pyqtSignal(str)
    
    def run(self):
        drivers = []
        try:
            # Get driver list via PowerShell (CIM is faster and more reliable)
            ps_cmd = """
            Get-CimInstance Win32_PnPSignedDriver |
            Select-Object DeviceName, DriverVersion, DriverDate, Manufacturer,
                          InfName, Status, DeviceID, DriverProviderName |
            ConvertTo-Json -Depth 3
            """

            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-WindowStyle", "Hidden",
                    "-Command", ps_cmd,
                ],
                capture_output=True,
                text=True,
                timeout=120,
                creationflags=creation_flags,
            )

            if result.returncode != 0 or not result.stdout.strip():
                error_msg = result.stderr.strip() or "Driver scan returned no data."
                self.error.emit(error_msg)
                self.drivers_ready.emit([])
                return
            
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                except json.JSONDecodeError as e:
                    self.error.emit(f"Failed to parse driver scan output: {e}")
                    self.drivers_ready.emit([])
                    return
                if not isinstance(data, list):
                    data = [data]
                    
                total = len(data)
                for i, driver in enumerate(data):
                    self.progress.emit(int((i / total) * 100))
                    
                    if driver.get('DeviceName'):
                        drivers.append({
                            'name': driver.get('DeviceName', 'Unknown'),
                            'version': driver.get('DriverVersion', 'Unknown'),
                            'date': driver.get('DriverDate', 'Unknown'),
                            'manufacturer': driver.get('Manufacturer', 'Unknown'),
                            'inf': driver.get('InfName', 'Unknown'),
                            'status': driver.get('Status', 'Unknown'),
                            'device_id': driver.get('DeviceID', ''),
                            'provider': driver.get('DriverProviderName', 'Unknown')
                        })
                        
        except Exception as e:
            self.error.emit(f"Driver scan error: {e}")
            
        self.drivers_ready.emit(drivers)

class DriverManagerWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.drivers = []
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        # Header
        header = QLabel("Driver Management & Repair")
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: #f8fafc;")
        layout.addWidget(header)
        
        desc = QLabel("Analyze, backup, and repair corrupted or outdated drivers")
        desc.setStyleSheet("color: #94a3b8; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.btn_scan = QPushButton("🔍 Scan All Drivers")
        self.btn_scan.setObjectName("toolButton")
        self.btn_scan.clicked.connect(self.scan_drivers)
        toolbar.addWidget(self.btn_scan)
        
        self.btn_check_updates = QPushButton("🔄 Check for Updates")
        self.btn_check_updates.setObjectName("toolButton")
        self.btn_check_updates.clicked.connect(self.check_updates)
        toolbar.addWidget(self.btn_check_updates)
        
        toolbar.addStretch()
        
        self.btn_backup = QPushButton("💾 Backup Drivers")
        self.btn_backup.setObjectName("toolButton")
        self.btn_backup.clicked.connect(self.backup_drivers)
        toolbar.addWidget(self.btn_backup)
        
        self.btn_restore = QPushButton("📥 Restore Drivers")
        self.btn_restore.setObjectName("toolButton")
        self.btn_restore.clicked.connect(self.restore_drivers)
        toolbar.addWidget(self.btn_restore)
        
        layout.addLayout(toolbar)
        
        # Filter bar
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        filter_layout.addWidget(QLabel("Status:"))
        
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "OK", "Warning", "Critical"])
        self.status_filter.currentTextChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.status_filter)
        
        filter_layout.addWidget(QLabel("Type:"))
        self.type_filter = QComboBox()
        self.type_filter.addItems(["All", "Display", "Network", "Storage", "Audio", "Other"])
        self.type_filter.currentTextChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.type_filter)
        
        filter_layout.addStretch()
        
        self.cb_show_unsigned = QCheckBox("Show Unsigned Drivers Only")
        self.cb_show_unsigned.stateChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.cb_show_unsigned)
        
        layout.addLayout(filter_layout)
        
        # Driver table
        self.driver_table = QTableWidget()
        self.driver_table.setColumnCount(7)
        self.driver_table.setHorizontalHeaderLabels([
            "Device", "Manufacturer", "Version", "Date", "Status", "Signed", "Actions"
        ])
        self.driver_table.setStyleSheet("""
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
        """)
        self.driver_table.setMinimumHeight(400)
        layout.addWidget(self.driver_table)
        
        # Details panel
        details_group = QGroupBox("Driver Details & Issues")
        details_group.setStyleSheet("""
            QGroupBox {
                color: #38bdf8;
                font-weight: bold;
                border: 1px solid #334155;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        details_layout = QVBoxLayout(details_group)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(150)
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
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Styling
        self.setStyleSheet("""
            #toolButton {
                background-color: #334155;
                color: #f8fafc;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
            }
            #toolButton:hover {
                background-color: #475569;
            }
            QLabel {
                color: #f8fafc;
            }
            QComboBox {
                background-color: #1e293b;
                color: #f8fafc;
                border: 1px solid #334155;
                border-radius: 4px;
                padding: 5px;
            }
            QCheckBox {
                color: #f8fafc;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
        """)
        
    def scan_drivers(self):
        self.progress.setVisible(True)
        self.progress.setRange(0, 100)
        
        self.scan_thread = DriverScannerThread()
        self.scan_thread.drivers_ready.connect(self.on_drivers_scanned)
        self.scan_thread.progress.connect(self.progress.setValue)
        self.scan_thread.error.connect(self.on_driver_scan_error)
        self.scan_thread.start()
        
    def on_drivers_scanned(self, drivers):
        self.progress.setVisible(False)
        self.drivers = drivers
        self.populate_table(drivers)
        self.analyze_driver_issues(drivers)

    def on_driver_scan_error(self, message):
        self.progress.setVisible(False)
        QMessageBox.warning(self, "Driver Scan", message)
        self.details_text.setText(f"Driver scan failed:\n{message}")
        
    def populate_table(self, drivers):
        self.driver_table.setRowCount(0)
        
        for driver in drivers:
            row = self.driver_table.rowCount()
            self.driver_table.insertRow(row)
            
            # Device name
            name_item = QTableWidgetItem(driver['name'])
            if 'graphics' in driver['name'].lower() or 'nvidia' in driver['name'].lower() or 'amd' in driver['name'].lower():
                name_item.setIcon(self.style().standardIcon(self.style().StandardPixmap.SP_ComputerIcon))
            self.driver_table.setItem(row, 0, name_item)
            
            self.driver_table.setItem(row, 1, QTableWidgetItem(driver['manufacturer']))
            self.driver_table.setItem(row, 2, QTableWidgetItem(driver['version']))
            
            # Parse date
            date_str = driver['date']
            if date_str and date_str != 'Unknown':
                try:
                    # WMI date format: 20230101120000.000000+000
                    date_obj = datetime.strptime(date_str.split('.')[0], "%Y%m%d%H%M%S")
                    date_display = date_obj.strftime("%Y-%m-%d")
                    
                    # Check if older than 2 years
                    if (datetime.now() - date_obj).days > 730:
                        date_item = QTableWidgetItem(f"⚠️ {date_display}")
                        date_item.setForeground(QColor("#f59e0b"))
                    else:
                        date_item = QTableWidgetItem(date_display)
                except:
                    date_item = QTableWidgetItem(date_str)
            else:
                date_item = QTableWidgetItem("Unknown")
            self.driver_table.setItem(row, 3, date_item)
            
            # Status
            status = driver['status']
            status_item = QTableWidgetItem(status)
            if 'Error' in status or 'Problem' in status:
                status_item.setForeground(QColor("#ef4444"))
                status_item.setBackground(QColor("#450a0a"))
            elif 'OK' in status:
                status_item.setForeground(QColor("#10b981"))
            self.driver_table.setItem(row, 4, status_item)
            
            # Check if signed (simplified)
            signed = "Yes" if "microsoft" in driver['provider'].lower() or "intel" in driver['provider'].lower() else "Check"
            signed_item = QTableWidgetItem(signed)
            if signed == "Check":
                signed_item.setForeground(QColor("#f59e0b"))
            self.driver_table.setItem(row, 5, signed_item)
            
            # Action button
            btn = QPushButton("Repair")
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #0ea5e9;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 4px 8px;
                }
                QPushButton:hover {
                    background-color: #0284c7;
                }
            """)
            btn.clicked.connect(lambda checked, d=driver: self.repair_driver(d))
            self.driver_table.setCellWidget(row, 6, btn)
            
    def analyze_driver_issues(self, drivers):
        issues = []
        warnings = []
        
        for driver in drivers:
            # Check for old drivers
            if driver['date'] and driver['date'] != 'Unknown':
                try:
                    date_obj = datetime.strptime(driver['date'].split('.')[0], "%Y%m%d%H%M%S")
                    if (datetime.now() - date_obj).days > 730:
                        warnings.append(f"{driver['name']}: Driver is over 2 years old")
                except:
                    pass
            
            # Check for error status
            if 'Error' in driver['status'] or 'Problem' in driver['status']:
                issues.append(f"{driver['name']}: Driver reporting errors ({driver['status']})")
                
            # Check for common problematic drivers
            problematic = ['ntfs.sys', 'nvlddmkm.sys', 'atikmpag.sys', 'iaStorAC.sys']
            if any(p in driver.get('inf', '') for p in problematic):
                warnings.append(f"{driver['name']}: Known historically problematic driver")
        
        report = "=== DRIVER ANALYSIS REPORT ===\n\n"
        
        if issues:
            report += "CRITICAL ISSUES FOUND:\n"
            for issue in issues:
                report += f"  ❌ {issue}\n"
            report += "\n"
        else:
            report += "✓ No critical driver issues detected\n\n"
            
        if warnings:
            report += "WARNINGS:\n"
            for warning in warnings:
                report += f"  ⚠️ {warning}\n"
        else:
            report += "✓ No warnings"
            
        self.details_text.setText(report)
        
    def apply_filter(self):
        if not self.drivers:
            return
            
        filtered = self.drivers.copy()
        status = self.status_filter.currentText()
        driver_type = self.type_filter.currentText()
        
        if status != "All":
            filtered = [d for d in filtered if status.lower() in d['status'].lower()]
            
        if driver_type != "All":
            type_keywords = {
                'Display': ['graphics', 'nvidia', 'amd', 'intel', 'display'],
                'Network': ['network', 'ethernet', 'wifi', 'wireless', 'bluetooth'],
                'Storage': ['disk', 'storage', 'sata', 'nvme', 'scsi'],
                'Audio': ['audio', 'sound', 'realtek']
            }
            keywords = type_keywords.get(driver_type, [])
            filtered = [d for d in filtered if any(k in d['name'].lower() for k in keywords)]
            
        if self.cb_show_unsigned.isChecked():
            filtered = [d for d in filtered if d['provider'] == 'Unknown' or 'microsoft' not in d['provider'].lower()]
            
        self.populate_table(filtered)
        
    def repair_driver(self, driver):
        reply = QMessageBox.question(self, "Repair Driver", 
                                   f"Attempt to repair {driver['name']}?\n\nThis will disable and re-enable the device.",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                # Disable and re-enable device
                device_id = driver['device_id']
                subprocess.run(["powershell", "-Command", f"Disable-PnpDevice -InstanceId '{device_id}' -Confirm:$false"], 
                             capture_output=True)
                subprocess.run(["powershell", "-Command", f"Enable-PnpDevice -InstanceId '{device_id}' -Confirm:$false"], 
                             capture_output=True)
                QMessageBox.information(self, "Success", f"Driver {driver['name']} has been reset.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to repair driver: {str(e)}")
                
    def check_updates(self):
        self.details_text.append("\n[Checking Windows Update for driver updates...]")
        try:
            subprocess.Popen(["start", "ms-settings:windowsupdate"], shell=True)
        except:
            pass
            
    def backup_drivers(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Backup Directory")
        if folder:
            self.details_text.append(f"\n[Backing up drivers to {folder}...]")
            try:
                subprocess.run(["powershell", "-Command", f"Export-WindowsDriver -Online -Destination '{folder}\\DriverBackup'"], 
                             capture_output=True)
                QMessageBox.information(self, "Success", "Drivers backed up successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Backup failed: {str(e)}")
                
    def restore_drivers(self):
        QMessageBox.information(self, "Restore", "Please select the driver backup folder and device to restore.")