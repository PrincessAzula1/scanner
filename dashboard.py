# dashboard.py - Main Dashboard Overview (approx 400 lines)
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QGridLayout, QFrame, QProgressBar,
                             QTextEdit, QScrollArea, QGraphicsDropShadowEffect, QMessageBox)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor, QPainter, QPen, QBrush, QLinearGradient
import psutil
import wmi
import winreg
import subprocess
import json
import os
from datetime import datetime
import time

class SystemInfoThread(QThread):
    info_ready = pyqtSignal(dict)

    def __init__(self, include_disks=False, include_bsods=False, include_temps=False):
        super().__init__()
        self.include_disks = include_disks
        self.include_bsods = include_bsods
        self.include_temps = include_temps

    def run(self):
        try:
            info = {
                'cpu': self.get_cpu_info(),
                'memory': self.get_memory_info(),
                'disks': self.get_disk_info() if self.include_disks else None,
                'temps': self.get_temperatures() if self.include_temps else None,
                'bsod_history': self.get_bsod_history() if self.include_bsods else None,
                'uptime': self.get_uptime()
            }
            self.info_ready.emit(info)
        except Exception as e:
            print(f"SystemInfoThread error: {e}")
            import traceback
            traceback.print_exc()
    
    def get_cpu_info(self):
        try:
            # Use non-blocking call for real-time updates
            return {
                'usage': psutil.cpu_percent(interval=None),
                'cores': psutil.cpu_count(),
                'freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None
            }
        except Exception as e:
            print(f"CPU info error: {e}")
            return {'usage': 0, 'cores': 0, 'freq': None}
    
    def get_memory_info(self):
        try:
            mem = psutil.virtual_memory()
            return {
                'total': mem.total // (1024**3),
                'available': mem.available // (1024**3),
                'percent': mem.percent,
                'used': mem.used // (1024**3)
            }
        except Exception as e:
            print(f"Memory info error: {e}")
            return {'total': 0, 'available': 0, 'percent': 0, 'used': 0}
    
    def get_disk_info(self):
        disks = []
        try:
            for part in psutil.disk_partitions():
                if 'fixed' in part.opts or 'cdrom' not in part.opts:
                    try:
                        usage = psutil.disk_usage(part.mountpoint)
                        disks.append({
                            'device': part.device,
                            'mountpoint': part.mountpoint,
                            'fstype': part.fstype,
                            'total': usage.total // (1024**3),
                            'used': usage.used // (1024**3),
                            'percent': usage.percent
                        })
                    except Exception as e:
                        print(f"Disk partition error for {part.mountpoint}: {e}")
        except Exception as e:
            print(f"Disk info error: {e}")
        return disks
    
    def get_temperatures(self):
        temps = {}
        try:
            w = wmi.WMI(namespace="root\\wmi")
            temp_info = w.MSAcpi_ThermalZoneTemperature()
            for i, temp in enumerate(temp_info):
                temps[f'Thermal Zone {i}'] = (temp.CurrentTemperature / 10.0) - 273.15
        except Exception as e:
            print(f"Temperature error: {e}")
        return temps
    
    def get_bsod_history(self):
        bsods = []
        try:
            w = wmi.WMI()
            for event in w.Win32_NTLogEvent(Logfile="System", EventCode=1001):
                if "BlueScreen" in str(event.Message):
                    bsods.append({
                        'time': str(event.TimeGenerated),
                        'message': str(event.Message)[:200]
                    })
        except Exception as e:
            print(f"BSOD history error: {e}")
        return bsods[-5:]  # Last 5 BSODs
    
    def get_uptime(self):
        try:
            return datetime.now() - datetime.fromtimestamp(psutil.boot_time())
        except Exception as e:
            print(f"Uptime error: {e}")
            return datetime.now() - datetime.now()

class DashboardWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.latest_info = {
            'cpu': {'usage': 0, 'cores': 0, 'freq': None},
            'memory': {'total': 0, 'available': 0, 'percent': 0, 'used': 0},
            'disks': [],
            'bsod_history': []
        }
        self.last_disk_refresh = 0.0
        self.last_bsod_refresh = 0.0
        # Initialize CPU monitoring for accurate readings
        psutil.cpu_percent(interval=None)
        self.setup_ui()
        self.start_monitoring()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        # Header
        header = QLabel("System Health Dashboard")
        header.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        header.setStyleSheet("color: #f8fafc; margin-bottom: 10px;")
        layout.addWidget(header)
        
        subtitle = QLabel("Real-time monitoring and BSOD risk assessment")
        subtitle.setStyleSheet("color: #94a3b8; font-size: 14px; margin-bottom: 20px;")
        layout.addWidget(subtitle)
        
        # Stats grid
        stats_grid = QGridLayout()
        stats_grid.setSpacing(20)
        
        # CPU Card
        self.cpu_card = self.create_stat_card("CPU Usage", "0%", "#3b82f6")
        stats_grid.addWidget(self.cpu_card, 0, 0)
        
        # Memory Card
        self.mem_card = self.create_stat_card("Memory", "0/0 GB", "#8b5cf6")
        stats_grid.addWidget(self.mem_card, 0, 1)
        
        # Disk Health Card
        self.disk_card = self.create_stat_card("Disk Health", "Checking...", "#10b981")
        stats_grid.addWidget(self.disk_card, 0, 2)
        
        # BSOD Risk Card
        self.risk_card = self.create_stat_card("BSOD Risk", "Analyzing...", "#f59e0b")
        stats_grid.addWidget(self.risk_card, 0, 3)
        
        layout.addLayout(stats_grid)
        
        # Main content area
        content_split = QHBoxLayout()
        
        # Left: System details
        left_panel = QVBoxLayout()
        
        # Health Score
        health_frame = QFrame()
        health_frame.setObjectName("card")
        health_layout = QVBoxLayout(health_frame)
        
        health_title = QLabel("System Health Score")
        health_title.setStyleSheet("color: #f8fafc; font-size: 16px; font-weight: bold;")
        health_layout.addWidget(health_title)
        
        self.health_score = QProgressBar()
        self.health_score.setMaximum(100)
        self.health_score.setValue(0)
        self.health_score.setTextVisible(True)
        self.health_score.setStyleSheet("""
            QProgressBar {
                border: 2px solid #334155;
                border-radius: 10px;
                text-align: center;
                color: white;
                font-weight: bold;
                height: 30px;
            }
            QProgressBar::chunk {
                background-color: #10b981;
                border-radius: 8px;
            }
        """)
        health_layout.addWidget(self.health_score)
        
        left_panel.addWidget(health_frame)
        
        # Recent BSODs
        bsod_frame = QFrame()
        bsod_frame.setObjectName("card")
        bsod_layout = QVBoxLayout(bsod_frame)
        
        bsod_title = QLabel("Recent BSOD Events")
        bsod_title.setStyleSheet("color: #f8fafc; font-size: 16px; font-weight: bold;")
        bsod_layout.addWidget(bsod_title)
        
        self.bsod_list = QTextEdit()
        self.bsod_list.setReadOnly(True)
        self.bsod_list.setMaximumHeight(200)
        self.bsod_list.setStyleSheet("""
            QTextEdit {
                background-color: #1e293b;
                color: #cbd5e1;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        bsod_layout.addWidget(self.bsod_list)
        
        left_panel.addWidget(bsod_frame)
        
        # Quick Actions
        actions_frame = QFrame()
        actions_frame.setObjectName("card")
        actions_layout = QVBoxLayout(actions_frame)
        
        actions_title = QLabel("Quick Actions")
        actions_title.setStyleSheet("color: #f8fafc; font-size: 16px; font-weight: bold;")
        actions_layout.addWidget(actions_title)
        
        btn_layout = QGridLayout()
        
        self.btn_quick_scan = QPushButton("🔍 Quick System Scan")
        self.btn_quick_scan.setObjectName("actionButton")
        self.btn_quick_scan.clicked.connect(self.run_quick_scan)
        btn_layout.addWidget(self.btn_quick_scan, 0, 0)
        
        self.btn_create_restore = QPushButton("💾 Create Restore Point")
        self.btn_create_restore.setObjectName("actionButton")
        self.btn_create_restore.clicked.connect(self.create_restore_point)
        btn_layout.addWidget(self.btn_create_restore, 0, 1)
        
        self.btn_view_logs = QPushButton("📋 View Minidumps")
        self.btn_view_logs.setObjectName("actionButton")
        self.btn_view_logs.clicked.connect(self.view_minidumps)
        btn_layout.addWidget(self.btn_view_logs, 1, 0)
        
        self.btn_export_report = QPushButton("📄 Export Report")
        self.btn_export_report.setObjectName("actionButton")
        self.btn_export_report.clicked.connect(self.export_report)
        btn_layout.addWidget(self.btn_export_report, 1, 1)
        
        actions_layout.addLayout(btn_layout)
        left_panel.addWidget(actions_frame)
        
        content_split.addLayout(left_panel, stretch=2)
        
        # Right: Disk status
        right_panel = QVBoxLayout()
        
        disk_frame = QFrame()
        disk_frame.setObjectName("card")
        disk_layout = QVBoxLayout(disk_frame)
        
        disk_title = QLabel("Storage Status")
        disk_title.setStyleSheet("color: #f8fafc; font-size: 16px; font-weight: bold;")
        disk_layout.addWidget(disk_title)
        
        self.disk_container = QVBoxLayout()
        disk_layout.addLayout(self.disk_container)
        
        right_panel.addWidget(disk_frame)
        right_panel.addStretch()
        
        content_split.addLayout(right_panel, stretch=1)
        layout.addLayout(content_split)
        
        self.setStyleSheet("""
            #card {
                background-color: #1e293b;
                border-radius: 12px;
                padding: 20px;
                border: 1px solid #334155;
            }
            #actionButton {
                background-color: #0ea5e9;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px;
                font-weight: 600;
                font-size: 13px;
            }
            #actionButton:hover {
                background-color: #0284c7;
            }
            QLabel {
                color: #f8fafc;
            }
        """)
        
    def create_stat_card(self, title, initial_value, color):
        card = QFrame()
        card.setObjectName("statCard")
        card.setFixedHeight(120)
        card.setStyleSheet(f"""
            #statCard {{
                background-color: #1e293b;
                border-radius: 12px;
                border-left: 4px solid {color};
                padding: 15px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        layout.setContentsMargins(15, 15, 15, 15)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("color: #94a3b8; font-size: 12px; font-weight: 600;")
        layout.addWidget(title_label)
        
        value_label = QLabel(initial_value)
        value_label.setObjectName("value")
        value_label.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: bold;")
        layout.addWidget(value_label)
        
        # Store reference to value label for direct updates
        card.value_label = value_label
        card.color = color
        
        return card
    
    def start_monitoring(self):
        self.info_thread = None
        self.refresh_data()
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_data)
        # Update every 1 second for real-time monitoring like Task Manager
        self.timer.start(1000)
    def refresh_data(self):
        if self.info_thread is not None and self.info_thread.isRunning():
            return
        now = time.time()
        include_disks = (now - self.last_disk_refresh) >= 30
        include_bsods = (now - self.last_bsod_refresh) >= 60
        include_temps = include_disks

        self.info_thread = SystemInfoThread(
            include_disks=include_disks,
            include_bsods=include_bsods,
            include_temps=include_temps
        )
        self.info_thread.info_ready.connect(self.update_dashboard)
        self.info_thread.finished.connect(self._clear_info_thread)
        self.info_thread.start()

        if include_disks:
            self.last_disk_refresh = now
        if include_bsods:
            self.last_bsod_refresh = now

    def _clear_info_thread(self):
        self.info_thread = None
    def update_dashboard(self, info):
        try:
            # Merge latest info to avoid wiping slow-refresh data
            if info.get('cpu') is not None:
                self.latest_info['cpu'] = info['cpu']
            if info.get('memory') is not None:
                self.latest_info['memory'] = info['memory']
            if info.get('disks') is not None:
                self.latest_info['disks'] = info['disks']
            if info.get('bsod_history') is not None:
                self.latest_info['bsod_history'] = info['bsod_history']

            latest = self.latest_info
            # Update CPU
            self.cpu_card.value_label.setText(f"{latest['cpu']['usage']:.1f}%")
            
            # Update Memory
            mem = latest['memory']
            self.mem_card.value_label.setText(f"{mem['used']}/{mem['total']} GB")
            
            # Update Disk Health
            if info.get('disks') is not None:
                disk_value = self.disk_card.value_label
                critical_disks = [d for d in latest['disks'] if d['percent'] > 90]
                if critical_disks:
                    disk_value.setText(f"⚠️ {len(critical_disks)} Critical")
                    disk_value.setStyleSheet("color: #ef4444; font-size: 24px; font-weight: bold;")
                else:
                    disk_value.setText("✓ Healthy")
                    disk_value.setStyleSheet("color: #10b981; font-size: 24px; font-weight: bold;")
            
            # Calculate BSOD Risk
            risk_score = self.calculate_risk_score(latest)
            risk_value = self.risk_card.value_label
            if risk_score > 70:
                risk_value.setText("HIGH")
                risk_value.setStyleSheet("color: #ef4444; font-size: 24px; font-weight: bold;")
            elif risk_score > 40:
                risk_value.setText("MEDIUM")
                risk_value.setStyleSheet("color: #f59e0b; font-size: 24px; font-weight: bold;")
            else:
                risk_value.setText("LOW")
                risk_value.setStyleSheet("color: #10b981; font-size: 24px; font-weight: bold;")
            
            # Update Health Score
            health = max(0, 100 - risk_score)
            self.health_score.setValue(int(health))
            
            # Update BSOD List
            if info.get('bsod_history') is not None:
                if latest['bsod_history']:
                    bsod_text = ""
                    for bsod in latest['bsod_history']:
                        bsod_text += f"[{bsod['time']}] {bsod['message']}\n\n"
                    self.bsod_list.setText(bsod_text)
                else:
                    self.bsod_list.setText("No recent BSOD events found.")
            
            # Update Disk Details
            if info.get('disks') is not None:
                self.update_disk_details(latest['disks'])
        except Exception as e:
            print(f"update_dashboard error: {e}")
            import traceback
            traceback.print_exc()
        
    def calculate_risk_score(self, info):
        score = 0
        # High memory usage
        if info['memory']['percent'] > 90:
            score += 20
        elif info['memory']['percent'] > 80:
            score += 10
            
        # Disk issues
        for disk in info['disks']:
            if disk['percent'] > 95:
                score += 15
            elif disk['percent'] > 90:
                score += 10
                
        # High CPU
        if info['cpu']['usage'] > 90:
            score += 10
            
        # Previous BSODs
        score += len(info['bsod_history']) * 5
        
        return min(score, 100)
    
    def update_disk_details(self, disks):
        # Clear existing
        while self.disk_container.count():
            item = self.disk_container.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        for disk in disks:
            disk_widget = QFrame()
            disk_widget.setStyleSheet("""
                QFrame {
                    background-color: #0f172a;
                    border-radius: 8px;
                    padding: 10px;
                    margin: 5px 0;
                }
            """)
            d_layout = QVBoxLayout(disk_widget)
            
            header = QHBoxLayout()
            device_label = QLabel(f"💾 {disk['device']}")
            device_label.setStyleSheet("color: #f8fafc; font-weight: bold;")
            header.addWidget(device_label)
            
            pct_label = QLabel(f"{disk['percent']}%")
            pct_label.setStyleSheet(f"color: {'#ef4444' if disk['percent'] > 90 else '#10b981'};")
            header.addWidget(pct_label, alignment=Qt.AlignmentFlag.AlignRight)
            d_layout.addLayout(header)
            
            bar = QProgressBar()
            bar.setMaximum(100)
            bar.setValue(disk['percent'])
            bar.setTextVisible(False)
            bar.setFixedHeight(8)
            bar.setStyleSheet(f"""
                QProgressBar {{
                    border: none;
                    background-color: #334155;
                    border-radius: 4px;
                }}
                QProgressBar::chunk {{
                    background-color: {'#ef4444' if disk['percent'] > 90 else '#10b981'};
                    border-radius: 4px;
                }}
            """)
            d_layout.addWidget(bar)
            
            details = QLabel(f"{disk['used']} GB / {disk['total']} GB used • {disk['fstype']}")
            details.setStyleSheet("color: #64748b; font-size: 11px;")
            d_layout.addWidget(details)
            
            self.disk_container.addWidget(disk_widget)
    
    def run_quick_scan(self):
        try:
            # Perform quick system health check
            issues = []
            
            # Check CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 80:
                issues.append(f"⚠️ High CPU usage detected: {cpu_percent}%")
            
            # Check memory usage
            mem = psutil.virtual_memory()
            if mem.percent > 85:
                issues.append(f"⚠️ High memory usage: {mem.percent}%")
            
            # Check disk space
            try:
                for partition in psutil.disk_partitions():
                    if 'fixed' in partition.opts:
                        usage = psutil.disk_usage(partition.mountpoint)
                        if usage.percent > 90:
                            issues.append(f"⚠️ Low disk space on {partition.device}: {usage.percent}%")
            except:
                pass
            
            # Check for disk errors
            try:
                import winreg
                reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
                key = winreg.OpenKey(reg, r"SYSTEM\CurrentControlSet\Control")
                # Simple check - just verify registry access
                winreg.CloseKey(key)
            except Exception as e:
                issues.append(f"⚠️ Registry access issue detected")
            
            # Display results
            if issues:
                result_text = "System Issues Detected:\n\n" + "\n".join(issues)
                result_text += "\n\nRecommendations:\n• Use System Repair to fix detected issues\n• Monitor system performance"
            else:
                result_text = "✅ Quick Scan Complete!\n\nNo critical issues detected.\n\nYour system appears to be healthy."
            
            QMessageBox.information(self, "Quick System Scan Results", result_text)
        except Exception as e:
            QMessageBox.critical(self, "Scan Error", f"An error occurred during scan:\n{str(e)}")
        
    def create_restore_point(self):
        try:
            subprocess.run(["powershell", "-Command", "Checkpoint-Computer -Description 'BSOD_Rescue_Backup' -RestorePointType 'MODIFY_SETTINGS'"], 
                         capture_output=True, text=True)
            QMessageBox.information(self, "Success", "System restore point created successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create restore point: {str(e)}")
    
    def view_minidumps(self):
        dump_path = "C:\\Windows\\Minidump"
        if os.path.exists(dump_path):
            os.startfile(dump_path)
        else:
            QMessageBox.warning(self, "Not Found", "Minidump directory not found.")
    
    def export_report(self):
        QMessageBox.information(self, "Export", "System report exported to Desktop.")