# system_repair.py - SFC, DISM, Component Repair (approx 450 lines)
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QProgressBar, QTextEdit, QGroupBox,
                             QCheckBox, QMessageBox, QComboBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
import subprocess
import os
import re

class SystemRepairThread(QThread):
    progress = pyqtSignal(int)
    log = pyqtSignal(str)
    finished = pyqtSignal(bool, str)
    
    def __init__(self, operations):
        super().__init__()
        self.operations = operations
        self.running = True
        
    def run(self):
        total_ops = len(self.operations)
        results = []
        
        for i, op in enumerate(self.operations):
            if not self.running:
                break
                
            self.log.emit(f"\n{'='*50}")
            self.log.emit(f"Starting: {op['name']}")
            self.log.emit(f"{'='*50}\n")
            
            try:
                process = subprocess.Popen(
                    op['command'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    shell=True
                )
                
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        self.log.emit(output.strip())
                        
                return_code = process.poll()
                success = return_code == 0 or op.get('ignore_errors', False)
                results.append({'name': op['name'], 'success': success})
                
                self.progress.emit(int((i + 1) / total_ops * 100))
                
            except Exception as e:
                self.log.emit(f"ERROR: {str(e)}")
                results.append({'name': op['name'], 'success': False})
                
        all_success = all(r['success'] for r in results)
        summary = "\n".join([f"{'✓' if r['success'] else '✗'} {r['name']}" for r in results])
        self.finished.emit(all_success, summary)

class SystemRepairWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.repair_thread = None
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        # Header
        header = QLabel("System File Repair & Recovery")
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: #f8fafc;")
        layout.addWidget(header)
        
        desc = QLabel("Repair corrupted Windows system files and component store")
        desc.setStyleSheet("color: #94a3b8; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # Repair options
        options_group = QGroupBox("Repair Operations")
        options_group.setStyleSheet("""
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
        """)
        options_layout = QVBoxLayout(options_group)
        
        self.cb_sfc = QCheckBox("System File Checker (SFC /scannow)")
        self.cb_sfc.setChecked(True)
        self.cb_sfc.setStyleSheet("color: #f8fafc; padding: 5px;")
        options_layout.addWidget(self.cb_sfc)
        
        self.cb_dism_scan = QCheckBox("DISM ScanHealth (Component Store)")
        self.cb_dism_scan.setChecked(True)
        self.cb_dism_scan.setStyleSheet("color: #f8fafc; padding: 5px;")
        options_layout.addWidget(self.cb_dism_scan)
        
        self.cb_dism_restore = QCheckBox("DISM RestoreHealth (Repair Component Store)")
        self.cb_dism_restore.setChecked(True)
        self.cb_dism_restore.setStyleSheet("color: #f8fafc; padding: 5px;")
        options_layout.addWidget(self.cb_dism_restore)
        
        self.cb_chkdsk = QCheckBox("Check Disk (chkdsk /scan)")
        self.cb_chkdsk.setChecked(False)
        self.cb_chkdsk.setStyleSheet("color: #f8fafc; padding: 5px;")
        options_layout.addWidget(self.cb_chkdsk)
        
        self.cb_reset_winsock = QCheckBox("Reset Network Stack (Winsock)")
        self.cb_reset_winsock.setChecked(False)
        self.cb_reset_winsock.setStyleSheet("color: #f8fafc; padding: 5px;")
        options_layout.addWidget(self.cb_reset_winsock)
        
        self.cb_rebuild_bcd = QCheckBox("Rebuild BCD Store (Boot Configuration)")
        self.cb_rebuild_bcd.setChecked(False)
        self.cb_rebuild_bcd.setStyleSheet("color: #f8fafc; padding: 5px;")
        options_layout.addWidget(self.cb_rebuild_bcd)
        
        layout.addWidget(options_group)
        
        # Preset buttons
        preset_layout = QHBoxLayout()
        
        self.btn_preset_quick = QPushButton("⚡ Quick Repair")
        self.btn_preset_quick.setObjectName("presetButton")
        self.btn_preset_quick.clicked.connect(self.preset_quick)
        preset_layout.addWidget(self.btn_preset_quick)
        
        self.btn_preset_deep = QPushButton("🔬 Deep Repair")
        self.btn_preset_deep.setObjectName("presetButton")
        self.btn_preset_deep.clicked.connect(self.preset_deep)
        preset_layout.addWidget(self.btn_preset_deep)
        
        self.btn_preset_boot = QPushButton("🚀 Boot Repair")
        self.btn_preset_boot.setObjectName("presetButton")
        self.btn_preset_boot.clicked.connect(self.preset_boot)
        preset_layout.addWidget(self.btn_preset_boot)
        
        preset_layout.addStretch()
        
        layout.addLayout(preset_layout)
        
        # Control buttons
        control_layout = QHBoxLayout()
        
        self.btn_start = QPushButton("▶ Start Repair")
        self.btn_start.setObjectName("startButton")
        self.btn_start.clicked.connect(self.start_repair)
        control_layout.addWidget(self.btn_start)
        
        self.btn_stop = QPushButton("⏹ Stop")
        self.btn_stop.setObjectName("stopButton")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_repair)
        control_layout.addWidget(self.btn_stop)
        
        control_layout.addStretch()
        
        self.btn_advanced = QPushButton("⚙ Advanced Options")
        self.btn_advanced.setObjectName("toolButton")
        self.btn_advanced.clicked.connect(self.show_advanced)
        control_layout.addWidget(self.btn_advanced)
        
        layout.addLayout(control_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setStyleSheet("""
            QProgressBar {
                border: 2px solid #334155;
                border-radius: 5px;
                text-align: center;
                color: white;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #10b981;
            }
        """)
        layout.addWidget(self.progress)
        
        # Log output
        log_group = QGroupBox("Repair Log")
        log_group.setStyleSheet("""
            QGroupBox {
                color: #38bdf8;
                font-weight: bold;
                border: 1px solid #334155;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        log_layout = QVBoxLayout(log_group)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #cbd5e1;
                border: none;
                font-family: 'Consolas', monospace;
                font-size: 12px;
            }
        """)
        log_layout.addWidget(self.log_text)
        
        layout.addWidget(log_group)
        
        # Info panel
        info_group = QGroupBox("What These Tools Do")
        info_group.setStyleSheet("""
            QGroupBox {
                color: #38bdf8;
                font-weight: bold;
                border: 1px solid #334155;
                border-radius: 8px;
            }
        """)
        info_layout = QVBoxLayout(info_group)
        
        info_text = QLabel("""
<b>SFC (System File Checker):</b> Scans and repairs corrupted Windows system files<br>
<b>DISM ScanHealth:</b> Checks if the component store is repairable<br>
<b>DISM RestoreHealth:</b> Repairs the component store using Windows Update<br>
<b>CHKDSK:</b> Checks file system integrity and bad sectors on disk<br>
<b>Winsock Reset:</b> Repairs network-related system files<br>
<b>BCD Rebuild:</b> Fixes boot configuration data issues
        """)
        info_text.setStyleSheet("color: #cbd5e1; line-height: 1.6;")
        info_text.setWordWrap(True)
        info_layout.addWidget(info_text)
        
        layout.addWidget(info_group)
        
        self.setStyleSheet("""
            #presetButton {
                background-color: #334155;
                color: #f8fafc;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: 500;
            }
            #presetButton:hover {
                background-color: #475569;
            }
            #startButton {
                background-color: #10b981;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 30px;
                font-weight: bold;
                font-size: 14px;
            }
            #startButton:hover {
                background-color: #059669;
            }
            #stopButton {
                background-color: #ef4444;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 30px;
                font-weight: bold;
            }
            #stopButton:hover {
                background-color: #dc2626;
            }
            #toolButton {
                background-color: #475569;
                color: #f8fafc;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
            }
        """)
        
    def preset_quick(self):
        self.cb_sfc.setChecked(True)
        self.cb_dism_scan.setChecked(True)
        self.cb_dism_restore.setChecked(False)
        self.cb_chkdsk.setChecked(False)
        self.cb_reset_winsock.setChecked(False)
        self.cb_rebuild_bcd.setChecked(False)
        
    def preset_deep(self):
        self.cb_sfc.setChecked(True)
        self.cb_dism_scan.setChecked(True)
        self.cb_dism_restore.setChecked(True)
        self.cb_chkdsk.setChecked(True)
        self.cb_reset_winsock.setChecked(True)
        self.cb_rebuild_bcd.setChecked(False)
        
    def preset_boot(self):
        self.cb_sfc.setChecked(True)
        self.cb_dism_scan.setChecked(True)
        self.cb_dism_restore.setChecked(True)
        self.cb_chkdsk.setChecked(True)
        self.cb_reset_winsock.setChecked(False)
        self.cb_rebuild_bcd.setChecked(True)
        
    def start_repair(self):
        operations = []
        
        if self.cb_sfc.isChecked():
            operations.append({
                'name': 'System File Checker',
                'command': 'sfc /scannow',
                'ignore_errors': False
            })
            
        if self.cb_dism_scan.isChecked():
            operations.append({
                'name': 'DISM ScanHealth',
                'command': 'DISM /Online /Cleanup-Image /ScanHealth',
                'ignore_errors': False
            })
            
        if self.cb_dism_restore.isChecked():
            operations.append({
                'name': 'DISM RestoreHealth',
                'command': 'DISM /Online /Cleanup-Image /RestoreHealth',
                'ignore_errors': False
            })
            
        if self.cb_chkdsk.isChecked():
            operations.append({
                'name': 'Check Disk',
                'command': 'chkdsk C: /scan',
                'ignore_errors': True
            })
            
        if self.cb_reset_winsock.isChecked():
            operations.append({
                'name': 'Reset Winsock',
                'command': 'netsh winsock reset',
                'ignore_errors': False
            })
            
        if self.cb_rebuild_bcd.isChecked():
            operations.append({
                'name': 'Rebuild BCD',
                'command': 'bootrec /rebuildbcd',
                'ignore_errors': True
            })
            
        if not operations:
            QMessageBox.warning(self, "No Operations", "Please select at least one repair operation.")
            return
            
        self.log_text.clear()
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        
        self.repair_thread = SystemRepairThread(operations)
        self.repair_thread.progress.connect(self.progress.setValue)
        self.repair_thread.log.connect(self.log_text.append)
        self.repair_thread.finished.connect(self.on_repair_finished)
        self.repair_thread.start()
        
    def stop_repair(self):
        if self.repair_thread:
            self.repair_thread.running = False
            self.log_text.append("\n[User requested stop...]")
            
    def on_repair_finished(self, success, summary):
        self.progress.setVisible(False)
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        
        self.log_text.append(f"\n{'='*50}")
        self.log_text.append("REPAIR SUMMARY")
        self.log_text.append(f"{'='*50}")
        self.log_text.append(summary)
        
        if success:
            QMessageBox.information(self, "Repair Complete", "All operations completed successfully!\n\n" + summary)
        else:
            QMessageBox.warning(self, "Repair Issues", "Some operations encountered issues.\n\n" + summary)
            
    def show_advanced(self):
        QMessageBox.information(self, "Advanced Options", 
                              "Advanced repair options:\n\n"
                              "1. Offline repair (from WinRE)\n"
                              "2. Component cleanup\n"
                              "3. Reset Windows (keep files)\n"
                              "4. Clean install preparation\n\n"
                              "Use with caution.")