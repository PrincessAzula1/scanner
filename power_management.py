# power_management.py - Power & Fast Startup Settings (approx 350 lines)
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QCheckBox, QGroupBox, QTextEdit,
                             QMessageBox, QComboBox, QSlider)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
import subprocess
import winreg
import os

class PowerManagementWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.load_current_settings()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        # Header
        header = QLabel("Power Management & Fast Startup")
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: #f8fafc;")
        layout.addWidget(header)
        
        desc = QLabel("Fix BSODs related to power states, sleep, hibernation, and Fast Startup")
        desc.setStyleSheet("color: #94a3b8; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # Fast Startup section
        fs_group = QGroupBox("Fast Startup (Hybrid Boot)")
        fs_group.setStyleSheet(self.group_style())
        fs_layout = QVBoxLayout(fs_group)
        
        self.fs_status = QLabel("Status: Checking...")
        self.fs_status.setStyleSheet("color: #f8fafc; font-size: 16px;")
        fs_layout.addWidget(self.fs_status)
        
        fs_info = QLabel("Fast Startup can cause driver initialization issues and BSODs on some hardware.")
        fs_info.setStyleSheet("color: #94a3b8;")
        fs_info.setWordWrap(True)
        fs_layout.addWidget(fs_info)
        
        fs_buttons = QHBoxLayout()
        
        self.btn_disable_fs = QPushButton("Disable Fast Startup")
        self.btn_disable_fs.setObjectName("actionButton")
        self.btn_disable_fs.clicked.connect(lambda: self.set_fast_startup(False))
        fs_buttons.addWidget(self.btn_disable_fs)
        
        self.btn_enable_fs = QPushButton("Enable Fast Startup")
        self.btn_enable_fs.setObjectName("toolButton")
        self.btn_enable_fs.clicked.connect(lambda: self.set_fast_startup(True))
        fs_buttons.addWidget(self.btn_enable_fs)
        
        fs_buttons.addStretch()
        fs_layout.addLayout(fs_buttons)
        
        layout.addWidget(fs_group)
        
        # Sleep & Hibernate
        sleep_group = QGroupBox("Sleep & Hibernate Settings")
        sleep_group.setStyleSheet(self.group_style())
        sleep_layout = QVBoxLayout(sleep_group)
        
        self.cb_disable_sleep = QCheckBox("Disable Sleep (prevents sleep-related BSODs)")
        self.cb_disable_sleep.setStyleSheet("color: #f8fafc;")
        self.cb_disable_sleep.stateChanged.connect(self.toggle_sleep)
        sleep_layout.addWidget(self.cb_disable_sleep)
        
        self.cb_disable_hibernate = QCheckBox("Disable Hibernate (saves SSD space, prevents hibernation BSODs)")
        self.cb_disable_hibernate.setStyleSheet("color: #f8fafc;")
        self.cb_disable_hibernate.stateChanged.connect(self.toggle_hibernate)
        sleep_layout.addWidget(self.cb_disable_hibernate)
        
        self.cb_usb_suspend = QCheckBox("Disable USB Selective Suspend (fixes USB device power issues)")
        self.cb_usb_suspend.setStyleSheet("color: #f8fafc;")
        self.cb_usb_suspend.stateChanged.connect(self.toggle_usb_suspend)
        sleep_layout.addWidget(self.cb_usb_suspend)
        
        layout.addWidget(sleep_group)
        
        # Power Plan
        plan_group = QGroupBox("Power Plan Optimization")
        plan_group.setStyleSheet(self.group_style())
        plan_layout = QVBoxLayout(plan_group)
        
        plan_layout.addWidget(QLabel("Select Power Plan:"))
        self.plan_combo = QComboBox()
        self.plan_combo.addItems(["Balanced (recommended)", "High Performance", "Power Saver", "Ultimate Performance"])
        self.plan_combo.currentIndexChanged.connect(self.change_power_plan)
        plan_layout.addWidget(self.plan_combo)
        
        self.btn_optimize = QPushButton("⚡ Optimize for Stability")
        self.btn_optimize.setObjectName("actionButton")
        self.btn_optimize.clicked.connect(self.optimize_for_stability)
        plan_layout.addWidget(self.btn_optimize)
        
        layout.addWidget(plan_group)
        
        # Advanced
        adv_group = QGroupBox("Advanced Power Settings")
        adv_group.setStyleSheet(self.group_style())
        adv_layout = QVBoxLayout(adv_group)
        
        self.btn_open_powercfg = QPushButton("Open Advanced Power Settings")
        self.btn_open_powercfg.setObjectName("toolButton")
        self.btn_open_powercfg.clicked.connect(lambda: os.system("powercfg.cpl"))
        adv_layout.addWidget(self.btn_open_powercfg)
        
        self.btn_energy_report = QPushButton("Generate Energy Report")
        self.btn_energy_report.setObjectName("toolButton")
        self.btn_energy_report.clicked.connect(self.generate_energy_report)
        adv_layout.addWidget(self.btn_energy_report)
        
        layout.addWidget(adv_group)
        
        # Log
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(200)
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #cbd5e1;
                border: 1px solid #334155;
                border-radius: 8px;
                font-family: 'Consolas', monospace;
            }
        """)
        layout.addWidget(self.log_text)
        
        layout.addStretch()
        
        self.setStyleSheet("""
            #actionButton {
                background-color: #0ea5e9;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: 600;
            }
            #actionButton:hover {
                background-color: #0284c7;
            }
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
        
    def load_current_settings(self):
        # Check Fast Startup
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                               r"SYSTEM\CurrentControlSet\Control\Session Manager\Power")
            value, _ = winreg.QueryValueEx(key, "HiberbootEnabled")
            winreg.CloseKey(key)
            
            if value == 1:
                self.fs_status.setText("Status: ENABLED (May cause BSODs)")
                self.fs_status.setStyleSheet("color: #f59e0b; font-size: 16px;")
            else:
                self.fs_status.setText("Status: DISABLED (Recommended for stability)")
                self.fs_status.setStyleSheet("color: #10b981; font-size: 16px;")
        except:
            self.fs_status.setText("Status: Unknown")
            
        # Check Hibernate
        try:
            result = subprocess.run(["powercfg", "/hibernate"], capture_output=True, text=True)
            self.cb_disable_hibernate.setChecked("off" in result.stdout.lower())
        except:
            pass
            
    def set_fast_startup(self, enable):
        try:
            # Requires admin
            value = 1 if enable else 0
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                               r"SYSTEM\CurrentControlSet\Control\Session Manager\Power",
                               0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "HiberbootEnabled", 0, winreg.REG_DWORD, value)
            winreg.CloseKey(key)
            
            self.log_text.append(f"{'Enabled' if enable else 'Disabled'} Fast Startup")
            self.load_current_settings()
            
            QMessageBox.information(self, "Success", 
                                  f"Fast Startup has been {'enabled' if enable else 'disabled'}.\n\nPlease restart your computer for changes to take effect.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to modify Fast Startup: {str(e)}")
            
    def toggle_sleep(self, state):
        try:
            if state == Qt.CheckState.Checked.value:
                subprocess.run(["powercfg", "/change", "standby-timeout-ac", "0"])
                subprocess.run(["powercfg", "/change", "standby-timeout-dc", "0"])
                self.log_text.append("Disabled Sleep mode")
            else:
                subprocess.run(["powercfg", "/change", "standby-timeout-ac", "30"])
                subprocess.run(["powercfg", "/change", "standby-timeout-dc", "15"])
                self.log_text.append("Enabled Sleep mode (30min AC, 15min battery)")
        except Exception as e:
            self.log_text.append(f"Error: {str(e)}")
            
    def toggle_hibernate(self, state):
        try:
            if state == Qt.CheckState.Checked.value:
                subprocess.run(["powercfg", "/hibernate", "off"])
                self.log_text.append("Disabled Hibernate")
            else:
                subprocess.run(["powercfg", "/hibernate", "on"])
                self.log_text.append("Enabled Hibernate")
        except Exception as e:
            self.log_text.append(f"Error: {str(e)}")
            
    def toggle_usb_suspend(self, state):
        try:
            setting = "off" if state == Qt.CheckState.Checked.value else "on"
            subprocess.run(["powercfg", "/setacvalueindex", "scheme_current", "2a737441-1930-4402-8d77-b2bebba308a3", "48e6b7a6-50f5-4782-a5d4-53bb8f07e226", "0" if setting == "off" else "1"])
            subprocess.run(["powercfg", "/setactive", "scheme_current"])
            self.log_text.append(f"USB Selective Suspend: {setting}")
        except Exception as e:
            self.log_text.append(f"Error: {str(e)}")
            
    def change_power_plan(self, index):
        plans = {
            0: "381b4222-f694-41f0-9685-ff5bb260df2e",  # Balanced
            1: "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",  # High Performance
            2: "a1841308-3541-4fab-bc81-f71556f20b4a",  # Power Saver
            3: "e9a42b02-d5df-448d-aa00-03f14749eb61"   # Ultimate Performance
        }
        
        if index in plans:
            try:
                subprocess.run(["powercfg", "/setactive", plans[index]])
                self.log_text.append(f"Changed power plan to {self.plan_combo.currentText()}")
            except Exception as e:
                self.log_text.append(f"Error: {str(e)}")
                
    def optimize_for_stability(self):
        try:
            # Disable Fast Startup
            self.set_fast_startup(False)
            
            # Set High Performance
            subprocess.run(["powercfg", "/setactive", "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"])
            
            # Disable USB suspend
            subprocess.run(["powercfg", "/setacvalueindex", "scheme_current", "2a737441-1930-4402-8d77-b2bebba308a3", "48e6b7a6-50f5-4782-a5d4-53bb8f07e226", "0"])
            subprocess.run(["powercfg", "/setactive", "scheme_current"])
            
            # Disable PCI power management
            subprocess.run(["powercfg", "/setacvalueindex", "scheme_current", "501a4d13-42af-4429-9fd1-a8218c268e20", "ee12f906-d277-404b-b6da-e5fa1a576df5", "0"])
            
            self.log_text.append("Applied stability optimizations")
            QMessageBox.information(self, "Optimized", "Power settings optimized for maximum stability.\n\nChanges applied:\n• Fast Startup disabled\n• High Performance mode\n• USB suspend disabled\n• PCI power management disabled")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            
    def generate_energy_report(self):
        try:
            path = os.path.expanduser("~\\energy-report.html")
            subprocess.run(["powercfg", "/energy", "/output", path])
            self.log_text.append(f"Energy report saved to: {path}")
            os.startfile(path)
        except Exception as e:
            self.log_text.append(f"Error: {str(e)}")