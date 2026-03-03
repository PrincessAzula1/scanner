from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QProgressBar,
    QTextEdit,
    QMessageBox,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor
import subprocess
import json
import re
import time
import webbrowser
from datetime import datetime
from urllib.parse import quote, urlparse, parse_qs, unquote
from urllib.request import Request, urlopen


def _safe_text(value, default=""):
    if value is None:
        return default
    try:
        text = str(value).strip()
    except Exception:
        return default
    return text if text else default


class InstalledDriverScanThread(QThread):
    drivers_ready = pyqtSignal(list)
    progress = pyqtSignal(int)
    error = pyqtSignal(str)

    def run(self):
        drivers = []
        try:
            ps_cmd = """
            Get-CimInstance Win32_PnPSignedDriver |
            Select-Object DeviceName, DriverVersion, Manufacturer, DriverProviderName, DeviceID |
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
                encoding="utf-8",
                errors="replace",
                timeout=120,
                creationflags=creation_flags,
            )

            stdout_text = _safe_text(result.stdout)
            stderr_text = _safe_text(result.stderr)

            if result.returncode != 0 or not stdout_text:
                message = stderr_text or "Driver scan returned no data."
                self.error.emit(message)
                self.drivers_ready.emit([])
                return

            data = json.loads(stdout_text)
            if not isinstance(data, list):
                data = [data]

            total = max(len(data), 1)
            for i, item in enumerate(data):
                self.progress.emit(int((i / total) * 100))
                if not isinstance(item, dict):
                    continue

                name = _safe_text(item.get("DeviceName"))
                if not name:
                    continue
                drivers.append(
                    {
                        "name": name,
                        "version": _safe_text(item.get("DriverVersion"), "Unknown"),
                        "manufacturer": _safe_text(item.get("Manufacturer"), "Unknown"),
                        "provider": _safe_text(item.get("DriverProviderName"), "Unknown"),
                        "device_id": _safe_text(item.get("DeviceID")),
                    }
                )

            self.progress.emit(100)
        except Exception as exc:
            self.error.emit(f"Driver scan error: {exc}")

        self.drivers_ready.emit(drivers)


class OnlineDriverLookupThread(QThread):
    results_ready = pyqtSignal(list)
    progress = pyqtSignal(int)
    error = pyqtSignal(str)

    def __init__(self, drivers):
        super().__init__()
        self.drivers = drivers

    def run(self):
        results = []
        try:
            total = max(len(self.drivers), 1)
            for i, driver in enumerate(self.drivers):
                online_info = self.lookup_driver_online(driver)
                results.append({**driver, **online_info})
                self.progress.emit(int(((i + 1) / total) * 100))
                time.sleep(0.25)
        except Exception as exc:
            self.error.emit(f"Online lookup error: {exc}")

        self.results_ready.emit(results)

    def lookup_driver_online(self, driver):
        query = f"{driver['manufacturer']} {driver['name']} driver latest version download"
        source_url, html = self.fetch_search_result(query)

        online_version = self.extract_best_version(html)
        installed_version = driver.get("version", "Unknown")

        status = self.compare_versions(installed_version, online_version)

        return {
            "online_version": online_version,
            "status": status,
            "source": source_url,
            "last_checked": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def fetch_search_result(self, query):
        search_url = f"https://duckduckgo.com/html/?q={quote(query)}"
        req = Request(
            search_url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
            },
        )

        try:
            with urlopen(req, timeout=15) as response:
                html = response.read().decode("utf-8", errors="ignore")

            link_match = re.search(
                r'<a[^>]+class="result__a"[^>]+href="([^"]+)"', html, re.IGNORECASE
            )
            source = ""
            if link_match:
                raw_href = link_match.group(1)
                source = self.resolve_duckduckgo_redirect(raw_href)
            return source, html
        except Exception:
            return "", ""

    def resolve_duckduckgo_redirect(self, href):
        if "uddg=" in href:
            parsed = urlparse(href)
            query_params = parse_qs(parsed.query)
            encoded = query_params.get("uddg", [""])[0]
            return unquote(encoded)
        if href.startswith("http"):
            return href
        return ""

    def extract_best_version(self, html):
        if not html:
            return "Unknown"

        versions = re.findall(r"\b\d+(?:\.\d+){1,4}\b", html)
        if not versions:
            return "Unknown"

        cleaned = [v for v in versions if len(v) <= 20]
        if not cleaned:
            return "Unknown"

        cleaned.sort(key=self.version_tuple, reverse=True)
        return cleaned[0]

    def version_tuple(self, value):
        try:
            nums = [int(part) for part in re.findall(r"\d+", value)]
            return tuple(nums[:6])
        except Exception:
            return (0,)

    def compare_versions(self, installed, online):
        if not installed or installed == "Unknown":
            return "Unknown Local Version"
        if not online or online == "Unknown":
            return "Manual Review Needed"

        local_v = self.version_tuple(installed)
        online_v = self.version_tuple(online)

        if online_v > local_v:
            return "Update Available"
        return "Up To Date"


class AutoDriverUpdaterWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.drivers = []
        self.online_results = []
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        header = QLabel("Auto Driver Updater")
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: #f8fafc;")
        layout.addWidget(header)

        desc = QLabel(
            "Scans installed drivers, searches vendor pages online (manual internet search), and reports update status."
        )
        desc.setStyleSheet("color: #94a3b8; margin-bottom: 10px;")
        layout.addWidget(desc)

        toolbar = QHBoxLayout()

        self.btn_scan = QPushButton("🔍 Scan Installed Drivers")
        self.btn_scan.setObjectName("toolButton")
        self.btn_scan.clicked.connect(self.scan_installed_drivers)
        toolbar.addWidget(self.btn_scan)

        self.btn_online = QPushButton("🌐 Search Online Now")
        self.btn_online.setObjectName("toolButton")
        self.btn_online.clicked.connect(self.search_online_updates)
        toolbar.addWidget(self.btn_online)

        self.btn_refresh = QPushButton("🔄 Refresh")
        self.btn_refresh.setObjectName("toolButton")
        self.btn_refresh.clicked.connect(self.refresh_updates)
        toolbar.addWidget(self.btn_refresh)

        self.btn_auto_update = QPushButton("⚡ Auto Update")
        self.btn_auto_update.setObjectName("toolButton")
        self.btn_auto_update.clicked.connect(self.auto_update_drivers)
        toolbar.addWidget(self.btn_auto_update)

        toolbar.addStretch()
        layout.addLayout(toolbar)

        self.summary_label = QLabel("Status: Ready")
        self.summary_label.setStyleSheet("color: #cbd5e1; font-size: 13px;")
        layout.addWidget(self.summary_label)

        self.driver_table = QTableWidget()
        self.driver_table.setColumnCount(7)
        self.driver_table.setHorizontalHeaderLabels(
            [
                "Device",
                "Manufacturer",
                "Installed",
                "Online",
                "Status",
                "Source",
                "Last Checked",
            ]
        )
        self.driver_table.setMinimumHeight(420)
        self.driver_table.cellDoubleClicked.connect(self.open_source_link)
        self.driver_table.setStyleSheet(
            """
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
                padding: 8px;
                border: none;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 6px;
                border-bottom: 1px solid #334155;
            }
            """
        )
        layout.addWidget(self.driver_table)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(180)
        self.log_text.setStyleSheet(
            """
            QTextEdit {
                background-color: #0f172a;
                color: #cbd5e1;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 10px;
                font-family: 'Consolas', monospace;
            }
            """
        )
        layout.addWidget(self.log_text)

        self.setStyleSheet(
            """
            #toolButton {
                background-color: #334155;
                color: #f8fafc;
                border: none;
                border-radius: 6px;
                padding: 8px 14px;
            }
            #toolButton:hover {
                background-color: #475569;
            }
            QLabel {
                color: #f8fafc;
            }
            """
        )

    def scan_installed_drivers(self):
        self.progress.setVisible(True)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.summary_label.setText("Status: Scanning installed drivers...")
        self.log_text.append("[Local scan started]")

        self.scan_thread = InstalledDriverScanThread()
        self.scan_thread.progress.connect(self.progress.setValue)
        self.scan_thread.error.connect(self.on_scan_error)
        self.scan_thread.drivers_ready.connect(self.on_scan_complete)
        self.scan_thread.start()

    def on_scan_error(self, message):
        self.progress.setVisible(False)
        self.log_text.append(f"[Scan error] {message}")
        QMessageBox.warning(self, "Driver Scan", message)

    def on_scan_complete(self, drivers):
        self.drivers = drivers
        self.progress.setVisible(False)
        self.summary_label.setText(f"Status: Found {len(drivers)} installed drivers")
        self.log_text.append(f"[Local scan complete] Drivers found: {len(drivers)}")

        initial_rows = []
        for d in drivers:
            initial_rows.append(
                {
                    **d,
                    "online_version": "Not Checked",
                    "status": "Pending Online Search",
                    "source": "",
                    "last_checked": "-",
                }
            )
        self.online_results = initial_rows
        self.populate_table(self.online_results)

    def search_online_updates(self):
        if not self.drivers:
            QMessageBox.information(
                self,
                "Scan Needed",
                "Scan installed drivers first, then run online search.",
            )
            return

        self.progress.setVisible(True)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.summary_label.setText("Status: Searching internet for latest driver versions...")
        self.log_text.append("[Online scan started] Searching manually via web query...")

        self.lookup_thread = OnlineDriverLookupThread(self.drivers)
        self.lookup_thread.progress.connect(self.progress.setValue)
        self.lookup_thread.error.connect(self.on_online_error)
        self.lookup_thread.results_ready.connect(self.on_online_complete)
        self.lookup_thread.start()

    def on_online_error(self, message):
        self.progress.setVisible(False)
        self.log_text.append(f"[Online lookup error] {message}")
        QMessageBox.warning(self, "Online Lookup", message)

    def on_online_complete(self, results):
        self.online_results = results
        self.progress.setVisible(False)
        self.populate_table(results)

        update_count = len([r for r in results if r.get("status") == "Update Available"])
        uptodate_count = len([r for r in results if r.get("status") == "Up To Date"])
        review_count = len([r for r in results if r.get("status") == "Manual Review Needed"])

        self.summary_label.setText(
            f"Status: {uptodate_count} up to date | {update_count} updates | {review_count} manual review"
        )
        self.log_text.append(
            f"[Online scan complete] Up-to-date: {uptodate_count}, Updates: {update_count}, Review: {review_count}"
        )

    def refresh_updates(self):
        self.log_text.append("[Refresh requested]")
        self.search_online_updates()

    def populate_table(self, rows):
        self.driver_table.setRowCount(0)
        for row_data in rows:
            row = self.driver_table.rowCount()
            self.driver_table.insertRow(row)

            self.driver_table.setItem(row, 0, QTableWidgetItem(row_data.get("name", "Unknown")))
            self.driver_table.setItem(row, 1, QTableWidgetItem(row_data.get("manufacturer", "Unknown")))
            self.driver_table.setItem(row, 2, QTableWidgetItem(row_data.get("version", "Unknown")))
            self.driver_table.setItem(row, 3, QTableWidgetItem(row_data.get("online_version", "Unknown")))

            status_item = QTableWidgetItem(row_data.get("status", "Unknown"))
            status = row_data.get("status", "")
            if status == "Update Available":
                status_item.setForeground(QColor("#f59e0b"))
            elif status == "Up To Date":
                status_item.setForeground(QColor("#10b981"))
            elif status == "Manual Review Needed":
                status_item.setForeground(QColor("#38bdf8"))
            else:
                status_item.setForeground(QColor("#94a3b8"))
            self.driver_table.setItem(row, 4, status_item)

            source = row_data.get("source", "")
            source_item = QTableWidgetItem("Open Link" if source else "-")
            source_item.setData(Qt.ItemDataRole.UserRole, source)
            self.driver_table.setItem(row, 5, source_item)

            self.driver_table.setItem(row, 6, QTableWidgetItem(row_data.get("last_checked", "-")))

    def open_source_link(self, row, column):
        if column != 5:
            return
        source_item = self.driver_table.item(row, 5)
        if not source_item:
            return
        link = source_item.data(Qt.ItemDataRole.UserRole)
        if link:
            webbrowser.open(link)

    def auto_update_drivers(self):
        if not self.online_results:
            QMessageBox.information(self, "No Data", "Run scan and online search first.")
            return

        to_update = [r for r in self.online_results if r.get("status") == "Update Available"]
        if not to_update:
            QMessageBox.information(self, "Up To Date", "No pending driver updates found.")
            self.log_text.append("[Auto update] No updates needed.")
            return

        reply = QMessageBox.question(
            self,
            "Auto Update",
            (
                f"Found {len(to_update)} driver(s) with updates.\n\n"
                "This updater uses manual web source links (not Windows Update).\n"
                "Continue and open each source page now?"
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self.log_text.append("[Auto update] Starting online package update pass via winget...")
        winget_ok = False
        try:
            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            winget_cmd = [
                "winget",
                "upgrade",
                "--all",
                "--include-unknown",
                "--accept-source-agreements",
                "--accept-package-agreements",
            ]
            winget_result = subprocess.run(
                winget_cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=1800,
                creationflags=creation_flags,
            )
            winget_ok = winget_result.returncode == 0
            if winget_ok:
                self.log_text.append("[Auto update] winget completed successfully.")
            else:
                stderr = (winget_result.stderr or "").strip()
                self.log_text.append(f"[Auto update] winget finished with code {winget_result.returncode}: {stderr}")
        except FileNotFoundError:
            self.log_text.append("[Auto update] winget not found. Continuing with vendor source links.")
        except Exception as exc:
            self.log_text.append(f"[Auto update] winget execution error: {exc}")

        opened = 0
        for item in to_update:
            source = item.get("source")
            if source:
                webbrowser.open(source)
                opened += 1
                time.sleep(0.2)

        self.log_text.append(
            f"[Auto update] Opened {opened} vendor/source link(s). Install packages from those pages, then click Refresh."
        )
        QMessageBox.information(
            self,
            "Update Flow Started",
            (
                f"winget auto-update: {'Success' if winget_ok else 'Completed with warnings/partial'}\n"
                f"Opened {opened} source page(s).\n"
                "Install the latest driver(s) from those pages, then use Refresh to re-check status."
            ),
        )
