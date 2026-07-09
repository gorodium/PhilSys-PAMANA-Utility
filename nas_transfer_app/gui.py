import csv
import os
import queue
import threading
import time
import uuid
from pathlib import Path

from PySide6.QtCore import QEvent, Qt, QTimer
from PySide6.QtGui import QAction, QColor, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QStackedWidget,
    QSystemTrayIcon,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .config import (
    APP_DISPLAY_NAME,
    APP_SUBTITLE,
    DEFAULT_CHUNK_SIZE_MB,
    DEFAULT_MATRIX_DESTINATION_ROOT,
    DEFAULT_PARALLEL_WORKERS,
    LOG_DIR,
    MAX_CHUNK_SIZE_MB,
    MAX_PARALLEL_WORKERS,
    MIN_CHUNK_SIZE_MB,
    NAS_ENDPOINTS,
    REDMINE_MATRIX_ENDPOINTS,
    VERIFY_MODES,
    direction_endpoints,
    endpoint_by_name,
    load_settings,
    normalize_remote_path,
    resource_path,
    save_settings,
)
from .credentials import CredentialStore
from .logger_setup import create_logger
from .matrix_api import MatrixApiClient, MatrixApiError, MatrixCertificateError, build_matrix_matches, safe_token_preview
from .nas_client import NasClient, copy_remote_to_remote
from .packet_tools import PacketSearchResult, machine_folder_for_packet, packet_results_to_csv, parse_packet_input
from .state_db import STATUS_FAILED, STATUS_PENDING, StateDB
from .transfer_engine import TransferEngine


STATUS_COLORS = {
    "Pending": "#fff3cd",
    "Copying": "#d1ecf1",
    "Copied": "#d4edda",
    "Skipped": "#e2e3e5",
    "Verified": "#d4edda",
    "Failed": "#f8d7da",
    "Partially Copied": "#ffe8a1",
    "Found": "#d4edda",
    "Not found": "#f8d7da",
    "Ready": "#d1ecf1",
    "Manual review": "#fff3cd",
    "Packet not found": "#f8d7da",
    "Searching NAS": "#d1ecf1",
    "Packet Found": "#d4edda",
    "Packet Missing": "#f8d7da",
    "Ready to Execute": "#d4edda",
    "Executed": "#d4edda",
    "Executed ✓": "#d4edda",
    "Packet Copied to NAS ✓": "#d1ecf1",
    "Packet Copied — Comment Failed": "#ffe8a1",
    "Copy Failed": "#f8d7da",
    "Copy Unverified": "#ffe8a1",
    "Packet Not Copied": "#f8d7da",
    "Partial": "#ffe8a1",
    "Completed": "#d4edda",
    "Already Executed": "#d4edda",
}

THEMES = ("System", "Light", "Dark")

LIGHT_THEME = {
    "bg": "#f0f2f5",
    "panel": "#ffffff",
    "text": "#1a1a1a",
    "muted": "#6c757d",
    "border": "#dee2e6",
    "sidebar": "#0038A8",
    "sidebar_text": "#ffffff",
    "sidebar_active": "#002878",
    "input": "#ffffff",
    "table_header": "#f8f9fa",
    "accent": "#0038A8",
    "danger": "#CE1126",
    "warning": "#FCD116",
}

DARK_THEME = {
    "bg": "#121212",
    "panel": "#1e1e1e",
    "text": "#e0e0e0",
    "muted": "#9e9e9e",
    "border": "#333333",
    "sidebar": "#0a192f",
    "sidebar_text": "#ffffff",
    "sidebar_active": "#112240",
    "input": "#2d2d2d",
    "table_header": "#252525",
    "accent": "#3b82f6",
    "danger": "#ef4444",
    "warning": "#fbbf24",
}


def format_bytes(value):
    value = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} TB"


def format_eta(seconds):
    if seconds is None or seconds < 0:
        return "-"

    seconds = int(seconds)
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def status_badge(text="Disconnected"):
    label = QLabel(text)
    label.setAlignment(Qt.AlignCenter)
    label.setMinimumWidth(96)
    set_badge(label, text)
    return label


def set_badge(label, text):
    colors = {
        "Connected": ("#d4edda", "#155724"),
        "Disconnected": ("#e2e3e5", "#383d41"),
        "Testing": ("#d1ecf1", "#0c5460"),
        "Failed": ("#f8d7da", "#721c24"),
        "Error": ("#f8d7da", "#721c24"),
        "Ready": ("#d1ecf1", "#0c5460"),
        "Running": ("#d1ecf1", "#0c5460"),
        "Paused": ("#fff3cd", "#856404"),
        "Completed": ("#d4edda", "#155724"),
    }.get(text, ("#e2e3e5", "#383d41"))
    label.setText(text)
    label.setStyleSheet(
        "QLabel {"
        f"background: {colors[0]}; color: {colors[1]};"
        "border-radius: 4px; padding: 4px 8px; font-weight: 600;"
        "}"
    )


def readonly_item(value):
    item = QTableWidgetItem(str(value))
    item.setFlags(item.flags() & ~Qt.ItemIsEditable)
    return item


class CredentialBox(QGroupBox):
    def __init__(self, title):
        super().__init__(title)
        self.username = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.show_password = QCheckBox("Show")
        self.save_credentials = QCheckBox("Save credentials")
        self.status = status_badge("Disconnected")

        layout = QGridLayout(self)
        layout.addWidget(QLabel("Status"), 0, 0)
        layout.addWidget(self.status, 0, 1, 1, 2)
        layout.addWidget(QLabel("Username"), 1, 0)
        layout.addWidget(self.username, 1, 1, 1, 2)
        layout.addWidget(QLabel("Password"), 2, 0)
        layout.addWidget(self.password, 2, 1)
        layout.addWidget(self.show_password, 2, 2)
        layout.addWidget(self.save_credentials, 3, 1, 1, 2)

        self.show_password.toggled.connect(self.toggle_password)

    def toggle_password(self, checked):
        self.password.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)


class ProvinceProfileDialog(QDialog):
    def __init__(self, parent=None, profile=None):
        super().__init__(parent)
        self.setWindowTitle("Province NAS Profile")
        profile = profile or {}

        self.province = QLineEdit(profile.get("province", ""))
        self.label = QLineEdit(profile.get("label", ""))
        self.host = QLineEdit(profile.get("host", ""))
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(int(profile.get("port") or 2222))
        self.root = QLineEdit(profile.get("root", "/"))
        self.username = QLineEdit(profile.get("username", ""))
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText("Leave blank to keep saved password")
        self.show_password = QCheckBox("Show")
        self.show_password.toggled.connect(
            lambda checked: self.password.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
        )

        form = QFormLayout()
        form.addRow("Province name", self.province)
        form.addRow("NAS label", self.label)
        form.addRow("Host/IP/domain", self.host)
        form.addRow("Port", self.port)
        form.addRow("Default root path", self.root)
        form.addRow("Username", self.username)
        password_row = QWidget()
        password_layout = QHBoxLayout(password_row)
        password_layout.setContentsMargins(0, 0, 0, 0)
        password_layout.addWidget(self.password)
        password_layout.addWidget(self.show_password)
        form.addRow("Password", password_row)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def profile_data(self, existing_id=""):
        profile_id = existing_id or uuid.uuid4().hex
        province = self.province.text().strip()
        label = self.label.text().strip() or province or self.host.text().strip()
        return {
            "id": profile_id,
            "province": province,
            "label": label,
            "host": self.host.text().strip(),
            "port": self.port.value(),
            "root": normalize_remote_path(self.root.text()),
            "username": self.username.text().strip(),
        }, self.password.text()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_DISPLAY_NAME)
        self.setMinimumSize(760, 520)
        self.icon_path = resource_path("assets/nas_transfer_icon_new.png")
        self.logo_path = resource_path("assets/nas_transfer_icon_new.png")
        self.app_icon = QIcon(str(self.icon_path))
        if not self.app_icon.isNull():
            self.setWindowIcon(self.app_icon)

        self.settings = load_settings()
        self.credentials = CredentialStore(self.settings)
        self.db = StateDB()
        self.events = queue.Queue()
        self.pause_event = threading.Event()
        self.pause_event.set()
        self.cancel_event = threading.Event()
        self.matrix_cancel_event = threading.Event()
        self.packet_cancel_event = threading.Event()
        self.matrix_worker_thread = None
        self.worker_thread = None
        self.force_quit = False
        self.tray_icon = None
        self.current_job_key = None
        self.table_rows = {}
        self.packet_results = []
        self.matrix_matches = []
        self.last_data_done = 0
        self.last_speed_time = time.monotonic()
        self.current_speed = 0
        self.average_start_time = time.monotonic()
        self.app_logger, self.current_log_file = create_logger()

        self.build_ui()
        self.build_tray_icon()
        self.fit_initial_window_to_screen()
        self.load_settings_into_ui()
        self.load_saved_credentials()
        self.update_direction_labels()
        self.refresh_logs()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll_events)
        self.timer.start(250)

    def build_tray_icon(self):
        if not QSystemTrayIcon.isSystemTrayAvailable() or self.app_icon.isNull():
            return

        menu = QMenu(self)
        show_action = QAction(f"Show {APP_DISPLAY_NAME}", self)
        hide_action = QAction("Hide to Tray", self)
        quit_action = QAction("Quit", self)
        show_action.triggered.connect(self.show_from_tray)
        hide_action.triggered.connect(self.hide_to_tray)
        quit_action.triggered.connect(self.quit_from_tray)
        menu.addAction(show_action)
        menu.addAction(hide_action)
        menu.addSeparator()
        menu.addAction(quit_action)

        self.tray_icon = QSystemTrayIcon(self.app_icon, self)
        self.tray_icon.setToolTip(APP_DISPLAY_NAME)
        self.tray_icon.setContextMenu(menu)
        self.tray_icon.activated.connect(self.handle_tray_activation)
        self.tray_icon.show()

    def handle_tray_activation(self, reason):
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.show_from_tray()

    def show_from_tray(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def hide_to_tray(self):
        self.hide()
        if self.tray_icon:
            self.tray_icon.showMessage(
                APP_DISPLAY_NAME,
                "The app is still running in the system tray.",
                QSystemTrayIcon.Information,
                2500,
            )

    def quit_from_tray(self):
        self.force_quit = True
        if self.tray_icon:
            self.tray_icon.hide()
        QApplication.quit()

    def closeEvent(self, event):
        if self.force_quit or not self.tray_icon:
            super().closeEvent(event)
            return
        event.ignore()
        self.hide_to_tray()

    def changeEvent(self, event):
        super().changeEvent(event)

    def resolve_theme(self, theme_name=None):
        theme_name = theme_name or self.settings.get("theme", "System")
        if theme_name == "Dark":
            return DARK_THEME
        if theme_name == "Light":
            return LIGHT_THEME

        palette = QApplication.palette()
        return DARK_THEME if palette.window().color().lightness() < 128 else LIGHT_THEME

    def apply_theme(self, theme_name=None):
        colors = self.resolve_theme(theme_name)
        self.setStyleSheet(
            f"""
            QWidget {{ background: {colors['bg']}; color: {colors['text']}; font-family: "Segoe UI Variable", "Segoe UI", "Inter", sans-serif; font-size: 11pt; }}
            QLabel, QCheckBox, QRadioButton {{ background: transparent; }}
            QWidget#Sidebar {{ background: {colors['sidebar']}; border-right: 1px solid {colors['border']}; }}
            QWidget#Brand {{ background: {colors['sidebar']}; }}
            QLabel#BrandLogo {{ background: transparent; }}
            QLabel#BrandName {{ color: {colors['sidebar_text']}; font-size: 13pt; font-weight: bold; }}
            QLabel#BrandSubtitle {{ background: transparent; color: #a1b0d1; font-size: 10pt; }}
            QGroupBox {{ background: {colors['panel']}; border: 1px solid {colors['border']}; border-radius: 8px; margin-top: 6px; padding-top: 36px; font-weight: bold; font-size: 11pt; }}
            QGroupBox::title {{ subcontrol-origin: margin; left: 14px; top: 16px; padding: 0px; color: {colors['text']}; background: transparent; }}
            QPushButton {{ background: {colors['panel']}; color: {colors['text']}; border: 1px solid {colors['border']}; border-radius: 6px; min-height: 32px; padding: 6px 14px; font-weight: 500; }}
            QPushButton:hover {{ background: {colors['bg']}; border-color: {colors['accent']}; }}
            QPushButton:pressed {{ background: {colors['border']}; }}
            QPushButton:disabled {{ color: {colors['muted']}; background: {colors['bg']}; border-color: {colors['border']}; }}
            QPushButton#PrimaryButton {{ background: {colors['accent']}; color: white; border: none; font-weight: 600; }}
            QPushButton#PrimaryButton:hover {{ background: #0047D4; }}
            QPushButton#DangerButton {{ background: {colors['danger']}; color: white; border: none; font-weight: 600; }}
            QPushButton#DangerButton:hover {{ background: #a80e1f; }}
            QLineEdit, QComboBox, QSpinBox, QTextEdit {{ background: {colors['input']}; color: {colors['text']}; border: 1px solid {colors['border']}; border-radius: 6px; min-height: 32px; padding: 4px 8px; selection-background-color: {colors['accent']}; }}
            QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QTextEdit:focus {{ border: 1px solid {colors['accent']}; }}
            QTableWidget {{ background: {colors['panel']}; color: {colors['text']}; gridline-color: {colors['border']}; border: 1px solid {colors['border']}; border-radius: 8px; selection-background-color: {colors['accent']}; selection-color: white; alternate-background-color: {colors['bg']}; }}
            QHeaderView::section {{ background: {colors['table_header']}; color: {colors['muted']}; border: none; border-right: 1px solid {colors['border']}; border-bottom: 1px solid {colors['border']}; padding: 8px; font-weight: bold; text-transform: uppercase; font-size: 9pt; }}
            QTabWidget::pane {{ border: 1px solid {colors['border']}; border-radius: 8px; background: {colors['panel']}; }}
            QTabBar::tab {{ background: {colors['bg']}; color: {colors['muted']}; padding: 10px 16px; border: 1px solid {colors['border']}; border-bottom: none; border-top-left-radius: 6px; border-top-right-radius: 6px; margin-right: 2px; font-weight: bold; }}
            QTabBar::tab:selected {{ background: {colors['panel']}; color: {colors['accent']}; border-bottom: 2px solid {colors['accent']}; }}
            QListWidget {{ border: 0; background: {colors['sidebar']}; outline: 0; }}
            QListWidget::item {{ color: {colors['sidebar_text']}; padding: 12px 16px; border-radius: 6px; margin: 4px 12px; font-weight: 500; font-size: 11pt; }}
            QListWidget::item:selected {{ background: {colors['sidebar_active']}; color: white; font-weight: bold; border-left: 4px solid {colors['warning']}; border-top-left-radius: 0px; border-bottom-left-radius: 0px; }}
            QListWidget::item:hover:!selected {{ background: rgba(255, 255, 255, 0.1); color: white; }}
            QCheckBox {{ color: {colors['text']}; font-weight: 500; spacing: 8px; }}
            QCheckBox::indicator {{ width: 18px; height: 18px; border-radius: 4px; border: 1px solid {colors['border']}; background: {colors['input']}; }}
            QCheckBox::indicator:checked {{ background: {colors['accent']}; border: 1px solid {colors['accent']}; image: url('checked.png'); }}
            QProgressBar {{ border: 1px solid {colors['border']}; border-radius: 6px; text-align: center; background: {colors['input']}; color: {colors['text']}; font-weight: bold; }}
            QProgressBar::chunk {{ background: {colors['accent']}; border-radius: 5px; }}
            """
        )

    def fit_initial_window_to_screen(self):
        screen = QApplication.primaryScreen()
        if not screen:
            self.resize(1120, 680)
            return

        geometry = screen.availableGeometry()
        width = min(max(760, int(geometry.width() * 0.90)), max(480, geometry.width() - 40))
        height = min(max(600, int(geometry.height() * 0.86)), max(420, geometry.height() - 40))
        self.resize(width, height)
        frame = self.frameGeometry()
        frame.moveCenter(geometry.center())
        self.move(frame.topLeft())

    def build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)

        sidebar_panel = QWidget()
        sidebar_panel.setObjectName("Sidebar")
        sidebar_panel.setFixedWidth(340)
        sidebar_layout = QVBoxLayout(sidebar_panel)
        sidebar_layout.setContentsMargins(10, 12, 10, 10)

        brand = QWidget()
        brand.setObjectName("Brand")
        brand_layout = QHBoxLayout(brand)
        brand_layout.setContentsMargins(4, 0, 4, 8)
        logo = QLabel()
        logo.setObjectName("BrandLogo")
        logo_pixmap = QPixmap(str(self.logo_path))
        if not logo_pixmap.isNull():
            logo.setPixmap(logo_pixmap.scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo.setFixedSize(64, 64)
        brand_text = QVBoxLayout()
        app_name = QLabel(APP_DISPLAY_NAME)
        app_name.setObjectName("BrandName")
        app_name.setWordWrap(True)
        app_name.setAlignment(Qt.AlignCenter)
        app_subtitle = QLabel(APP_SUBTITLE)
        app_subtitle.setObjectName("BrandSubtitle")
        app_subtitle.setWordWrap(True)
        app_subtitle.setAlignment(Qt.AlignCenter)
        brand_text.addWidget(app_name)
        brand_text.addWidget(app_subtitle)
        brand_layout.addWidget(logo)
        brand_layout.addLayout(brand_text, stretch=1)
        sidebar_layout.addWidget(brand)

        self.sidebar = QListWidget()
        self.sidebar.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.sidebar.setWordWrap(True)
        sidebar_layout.addWidget(self.sidebar, stretch=1)
        self.stack = QStackedWidget()
        root.addWidget(sidebar_panel)
        root.addWidget(self.stack, stretch=1)

        pages = [
            ("NAS Migration", self.build_dashboard_page()),
            ("Packet Tracker", self.build_packet_page()),
            ("Matrix Restoration", self.build_matrix_page()),
            ("NAS Analytics", self.build_analytics_page()),
            ("Settings", self.build_settings_page()),
            ("Logs", self.build_logs_page()),
        ]

        for label, page in pages:
            item = QListWidgetItem(label)
            self.sidebar.addItem(item)
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QScrollArea.NoFrame)
            scroll.setWidget(page)
            self.stack.addWidget(scroll)

        self.sidebar.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.sidebar.setCurrentRow(0)
        self.apply_theme(self.settings.get("theme", "System"))

    def build_dashboard_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header = QLabel("NAS Migration")
        header.setStyleSheet("font-size: 22px; font-weight: 800; color: #0038A8;")
        layout.addWidget(header)

        cards = QGridLayout()
        cards.setSpacing(16)
        self.source_card = QGroupBox("Source NAS")
        self.destination_card = QGroupBox("Destination NAS")
        self.source_card_label = QLabel("-")
        self.source_host_label = QLabel("-")
        self.destination_card_label = QLabel("-")
        self.destination_host_label = QLabel("-")
        self.source_status = status_badge("Disconnected")
        self.destination_status = status_badge("Disconnected")
        self.source_path = QLineEdit("/")
        self.destination_path = QLineEdit("/")
        self.source_test_button = QPushButton("Test")
        self.destination_test_button = QPushButton("Test")
        self.source_test_button.clicked.connect(lambda _checked=False: self.test_nas_connection(self.source_endpoint_name()))
        self.destination_test_button.clicked.connect(lambda _checked=False: self.test_nas_connection(self.destination_endpoint_name()))

        for card, name_label, host_label, status_label, path_edit, test_button in (
            (self.source_card, self.source_card_label, self.source_host_label, self.source_status, self.source_path, self.source_test_button),
            (self.destination_card, self.destination_card_label, self.destination_host_label, self.destination_status, self.destination_path, self.destination_test_button),
        ):
            card_layout = QFormLayout(card)
            status_row = QWidget()
            status_layout = QHBoxLayout(status_row)
            status_layout.setContentsMargins(0, 0, 0, 0)
            status_layout.addWidget(status_label)
            status_layout.addWidget(test_button)
            status_layout.addStretch(1)
            card_layout.addRow("NAS", name_label)
            card_layout.addRow("IP/Host", host_label)
            card_layout.addRow("Connection", status_row)
            card_layout.addRow("Remote path", path_edit)

        cards.addWidget(self.source_card, 0, 0)
        cards.addWidget(self.destination_card, 0, 1)
        layout.addLayout(cards)

        options = QGroupBox("Transfer Setup")
        options_layout = QGridLayout(options)
        self.direction = QComboBox()
        self.direction.addItem("NAS1 to NAS2", "NAS1_TO_NAS2")
        self.direction.addItem("NAS2 to NAS1", "NAS2_TO_NAS1")
        self.direction.currentTextChanged.connect(self.update_direction_labels)
        self.operation = QComboBox()
        self.operation.addItem("Copy", "copy")
        self.operation.addItem("Move", "move")
        self.verification = QComboBox()
        self.verification.addItems(VERIFY_MODES)
        self.skip_verified = QCheckBox("Skip completed files on resume")
        self.retry_limit = QSpinBox()
        self.retry_limit.setRange(0, 10)
        self.parallel_workers = QSpinBox()
        self.parallel_workers.setRange(1, MAX_PARALLEL_WORKERS)
        self.chunk_size_mb = QSpinBox()
        self.chunk_size_mb.setRange(MIN_CHUNK_SIZE_MB, MAX_CHUNK_SIZE_MB)

        options_layout.addWidget(QLabel("Direction"), 0, 0)
        options_layout.addWidget(self.direction, 0, 1)
        options_layout.addWidget(QLabel("Operation"), 0, 2)
        options_layout.addWidget(self.operation, 0, 3)
        options_layout.addWidget(QLabel("Verification"), 1, 0)
        options_layout.addWidget(self.verification, 1, 1)
        options_layout.addWidget(QLabel("Retry limit"), 1, 2)
        options_layout.addWidget(self.retry_limit, 1, 3)
        options_layout.addWidget(QLabel("Parallel transfers"), 2, 0)
        options_layout.addWidget(self.parallel_workers, 2, 1)
        options_layout.addWidget(QLabel("Chunk size (MB)"), 2, 2)
        options_layout.addWidget(self.chunk_size_mb, 2, 3)
        options_layout.addWidget(self.skip_verified, 3, 0, 1, 4)
        layout.addWidget(options)

        button_row = QHBoxLayout()
        buttons = [
            ("Start Transfer", self.start_transfer),
            ("Pause", self.pause_transfer),
            ("Resume", self.resume_transfer),
            ("Stop / Cancel", self.cancel_transfer),
            ("Verify Existing Files", self.verify_existing),
            ("Open Logs", self.open_logs),
            ("Open Destination Folder", self.open_destination_folder),
        ]
        for label, slot in buttons:
            button = QPushButton(label)
            if label == "Start Transfer":
                button.setObjectName("PrimaryButton")
            if label == "Stop / Cancel":
                button.setObjectName("DangerButton")
            button.clicked.connect(slot)
            button_row.addWidget(button)
        button_row.addStretch(1)
        layout.addLayout(button_row)

        layout.addWidget(self.build_progress_panel())
        layout.addWidget(self.build_file_list_panel(), stretch=1)
        return page

    def build_progress_panel(self):
        group = QGroupBox("Progress Summary")
        layout = QGridLayout(group)
        self.status = status_badge("Ready")
        self.current_file = QLabel("-")
        self.current_file.setWordWrap(True)
        self.overall_progress = QProgressBar()
        self.file_progress = QProgressBar()
        self.metric_labels = {}

        layout.addWidget(QLabel("Status"), 0, 0)
        layout.addWidget(self.status, 0, 1)
        layout.addWidget(QLabel("Current file"), 0, 2)
        layout.addWidget(self.current_file, 0, 3)
        layout.addWidget(QLabel("Overall"), 1, 0)
        layout.addWidget(self.overall_progress, 1, 1, 1, 3)
        layout.addWidget(QLabel("Current file"), 2, 0)
        layout.addWidget(self.file_progress, 2, 1, 1, 3)

        metrics = [
            "Total files",
            "Completed",
            "Skipped",
            "Verified",
            "Pending",
            "Failed",
            "Total size",
            "Data done",
            "Live speed",
            "Average speed",
            "ETA",
        ]
        for index, label in enumerate(metrics):
            row = 3 + index // 4
            col = (index % 4) * 2
            value = QLabel("0" if "speed" not in label.lower() and label != "ETA" else "-")
            value.setStyleSheet("font-weight: 600;")
            self.metric_labels[label] = value
            layout.addWidget(QLabel(label), row, col)
            layout.addWidget(value, row, col + 1)

        return group

    def build_file_list_panel(self):
        self.file_list_group = QGroupBox("File List / Activity Details")
        self.file_list_group.setCheckable(True)
        self.file_list_group.setChecked(False)
        layout = QVBoxLayout(self.file_list_group)
        filter_row = QHBoxLayout()
        self.file_filter = QLineEdit()
        self.file_filter.setPlaceholderText("Search file, path, status, or error")
        self.file_filter.textChanged.connect(self.apply_file_filter)
        filter_row.addWidget(QLabel("Filter"))
        filter_row.addWidget(self.file_filter)
        layout.addLayout(filter_row)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["File name", "Source path", "Destination path", "Size", "Status", "Error message", "Last updated"]
        )
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_file_context_menu)
        layout.addWidget(self.table)
        self.file_list_group.toggled.connect(self.table.setVisible)
        self.file_list_group.toggled.connect(self.file_filter.setVisible)
        self.table.setVisible(False)
        self.file_filter.setVisible(False)
        return self.file_list_group

    def build_packet_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        header = QLabel("Packet Tracker")
        header.setStyleSheet("font-size: 22px; font-weight: 800; color: #0038A8;")
        layout.addWidget(header)

        controls = QGroupBox("Packet Search")
        grid = QGridLayout(controls)
        self.packet_scope = QComboBox()
        self.packet_scope.addItems(["Both NAS", "NAS1 only", "NAS2 only", "Province NAS"])
        self.packet_scope.currentTextChanged.connect(
            lambda _text: self.packet_province_profile.setEnabled(self.packet_scope.currentText() == "Province NAS")
        )
        self.packet_province_profile = QComboBox()
        self.packet_province_profile.currentIndexChanged.connect(
            lambda _index: self.settings.__setitem__(
                "packet_province_profile_id",
                self.selected_packet_province_profile_id(),
            )
        )
        self.packet_search_root = QLineEdit("/")
        self.packet_target_nas = QComboBox()
        self.packet_target_nas.addItems(["NAS1", "NAS2"])
        self.packet_target_folder = QLineEdit(DEFAULT_MATRIX_DESTINATION_ROOT)
        self.packet_input = QTextEdit()
        self.packet_input.setPlaceholderText("Enter packet IDs separated by comma, space, or new line.")
        self.packet_input.setFixedHeight(92)
        self.packet_count_label = QLabel("0 packet IDs detected.")
        self.packet_input.textChanged.connect(self.update_packet_count_preview)

        grid.addWidget(QLabel("Search scope"), 0, 0)
        grid.addWidget(self.packet_scope, 0, 1)
        grid.addWidget(QLabel("Search root"), 0, 2)
        grid.addWidget(self.packet_search_root, 0, 3)
        grid.addWidget(QLabel("Province profile"), 1, 0)
        grid.addWidget(self.packet_province_profile, 1, 1)
        grid.addWidget(QLabel("Target NAS"), 2, 0)
        grid.addWidget(self.packet_target_nas, 2, 1)
        grid.addWidget(QLabel("Target folder"), 2, 2)
        grid.addWidget(self.packet_target_folder, 2, 3)
        grid.addWidget(QLabel("Packet IDs"), 3, 0)
        grid.addWidget(self.packet_input, 3, 1, 1, 3)
        grid.addWidget(self.packet_count_label, 4, 1, 1, 3)
        layout.addWidget(controls)

        buttons = QHBoxLayout()
        for label, slot in [
            ("Import TXT/CSV List", self.import_packet_list),
            ("Search Packets", self.search_packets),
            ("Copy Selected", self.copy_selected_packets),
            ("Download Selected", self.download_selected_packets),
            ("Download All", self.download_all_packets),
            ("Upload Local Packet", self.upload_local_packets),
            ("Create Folder", self.create_packet_folder),
            ("Export CSV", self.export_packet_results),
        ]:
            button = QPushButton(label)
            if label == "Search Packets":
                button.setObjectName("PrimaryButton")
            button.clicked.connect(slot)
            buttons.addWidget(button)
        self.packet_cancel_button = QPushButton("Cancel Search")
        self.packet_cancel_button.clicked.connect(self.cancel_packet_search)
        buttons.addWidget(self.packet_cancel_button)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        packet_status_row = QHBoxLayout()
        self.packet_status = QLabel("Ready")
        self.packet_progress = QProgressBar()
        self.packet_progress.setTextVisible(True)
        self.packet_progress.setValue(0)
        self.packet_progress.setMaximum(1)
        packet_status_row.addWidget(self.packet_status)
        packet_status_row.addWidget(self.packet_progress, stretch=1)
        layout.addLayout(packet_status_row)

        result_filter = QHBoxLayout()
        self.packet_result_filter = QLineEdit()
        self.packet_result_filter.setPlaceholderText("Filter packet results")
        self.packet_result_filter.textChanged.connect(self.apply_packet_result_filter)
        result_filter.addWidget(QLabel("Filter"))
        result_filter.addWidget(self.packet_result_filter)
        layout.addLayout(result_filter)

        self.packet_table = QTableWidget(0, 10)
        self.packet_table.setHorizontalHeaderLabels(
            [
                "Select",
                "Packet ID",
                "Packet Name",
                "NAS Source",
                "Province/Profile",
                "Found Location",
                "Size",
                "Last Modified",
                "Status",
                "Error/Notes",
            ]
        )
        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.packet_table.setSortingEnabled(True)
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.packet_table, stretch=1)
        return page

    def build_matrix_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        header = QLabel("Matrix Packet Restoration Automation")
        header.setStyleSheet("font-size: 22px; font-weight: 800; color: #0038A8;")
        layout.addWidget(header)

        summary = QLabel(
            "Fetch assigned Matrix tickets, detect restoration packet IDs, locate packets, and prepare restoration actions."
        )
        summary.setWordWrap(True)
        layout.addWidget(summary)

        controls = QGroupBox("Matrix Workflow")
        grid = QGridLayout(controls)
        self.matrix_scope = QComboBox()
        self.matrix_scope.addItems(["Both NAS", "NAS1 only", "NAS2 only", "Selected Province NAS"])
        self.matrix_scope.currentTextChanged.connect(
            lambda _text: self.matrix_province_profile.setEnabled(
                self.matrix_scope.currentText() == "Selected Province NAS"
            )
        )
        self.matrix_province_profile = QComboBox()
        self.matrix_province_profile.currentIndexChanged.connect(
            lambda _index: self.settings.__setitem__(
                "matrix_province_profile_id",
                self.selected_matrix_province_profile_id(),
            )
        )
        self.matrix_allow_self_signed = QCheckBox("Allow internal/self-signed certificate")
        self.matrix_allow_partial = QCheckBox("Allow partial processing")
        self.matrix_ticket_numbers = QLineEdit()
        self.matrix_ticket_numbers.setPlaceholderText("Optional ticket number(s), e.g. 625042")
        self.matrix_fetch_button = QPushButton("Fetch Assigned Tickets")
        self.matrix_preview_button = QPushButton("Sync Ticket and Packet")
        self.matrix_execute_button = QPushButton("Execute Selected")
        self.matrix_execute_all_button = QPushButton("Execute All")
        self.matrix_cancel_button = QPushButton("Cancel Search")
        self.matrix_select_all_button = QPushButton("Select All")
        self.matrix_fetch_button.clicked.connect(self.fetch_matrix_tickets)
        self.matrix_preview_button.clicked.connect(self.preview_matrix_actions)
        self.matrix_execute_button.clicked.connect(self.execute_matrix_actions)
        self.matrix_execute_all_button.clicked.connect(self.execute_all_matrix_actions)
        self.matrix_cancel_button.clicked.connect(self.cancel_matrix_search)
        self.matrix_select_all_button.clicked.connect(self.toggle_matrix_select_all)

        grid.addWidget(QLabel("NAS search scope"), 0, 0)
        grid.addWidget(self.matrix_scope, 0, 1)
        grid.addWidget(QLabel("Province profile"), 0, 2)
        grid.addWidget(self.matrix_province_profile, 0, 3)
        grid.addWidget(self.matrix_allow_partial, 1, 0)
        grid.addWidget(self.matrix_allow_self_signed, 1, 1, 1, 2)
        grid.addWidget(QLabel("Specific ticket(s)"), 2, 0)
        grid.addWidget(self.matrix_ticket_numbers, 2, 1, 1, 3)
        grid.addWidget(self.matrix_fetch_button, 3, 0)
        grid.addWidget(self.matrix_preview_button, 3, 1)
        grid.addWidget(self.matrix_execute_button, 3, 2)
        grid.addWidget(self.matrix_execute_all_button, 3, 3)
        grid.addWidget(self.matrix_select_all_button, 4, 0)
        
        self.matrix_select_ready_button = QPushButton("Select Ready to Execute")
        self.matrix_select_ready_button.clicked.connect(self.select_ready_to_execute_matrix_matches)
        grid.addWidget(self.matrix_select_ready_button, 4, 1)

        grid.addWidget(self.matrix_cancel_button, 4, 3)
        self.matrix_fetch_button.setObjectName("PrimaryButton")
        self.matrix_preview_button.setObjectName("PrimaryButton")
        self.matrix_execute_all_button.setObjectName("DangerButton")
        layout.addWidget(controls)

        status_row = QHBoxLayout()
        self.matrix_status = QLabel("Ready")
        self.matrix_progress = QProgressBar()
        self.matrix_progress.setTextVisible(True)
        self.matrix_progress.setValue(0)
        status_row.addWidget(self.matrix_status)
        status_row.addWidget(self.matrix_progress, stretch=1)
        layout.addLayout(status_row)
        self.matrix_table = QTableWidget(0, 12)
        self.matrix_table.setWordWrap(True)
        self.matrix_table.setHorizontalHeaderLabels(
            [
                "Select",
                "Ticket",
                "Packet IDs",
                "Comment author",
                "Destination folder",
                "Due date",
                "Found packets",
                "Province/NAS Source",
                "Status",
                "Error",
                "Pkt Copied",
                "Commented",
            ]
        )
        self.matrix_table.setSelectionBehavior(QAbstractItemView.SelectItems)
        self.matrix_table.setSortingEnabled(True)
        self.matrix_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.matrix_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.matrix_table.customContextMenuRequested.connect(self.show_matrix_context_menu)
        layout.addWidget(self.matrix_table, stretch=1)
        return page

    def build_analytics_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
    
        # Header
        header_layout = QHBoxLayout()
        titles_layout = QVBoxLayout()
        header = QLabel("NAS Packet Analytics")
        header.setStyleSheet("font-size: 24px; font-weight: 800; color: #0038A8;")
        subtitle = QLabel("Read-only consolidated packet count from NAS1 and NAS2")
        subtitle.setStyleSheet("color: #555555; font-size: 12px;")
    
        # Badge
        badge = QLabel("Read-only mode")
        badge.setStyleSheet("background: #e2e3e5; color: #383d41; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold;")
    
        tt_layout = QHBoxLayout()
        tt_layout.addWidget(header)
        tt_layout.addWidget(badge)
        tt_layout.addStretch()
    
        titles_layout.addLayout(tt_layout)
        titles_layout.addWidget(subtitle)
    
        # Controls
        controls_layout = QHBoxLayout()
        self.analytics_status = QLabel("Ready")
        self.analytics_status.setStyleSheet("color: #666;")
    
        self.analytics_sync_btn = QPushButton("Scan Now")
        self.analytics_sync_btn.setObjectName("PrimaryButton")
        self.analytics_sync_btn.setFixedWidth(140)
        self.analytics_sync_btn.clicked.connect(self.sync_nas_analytics)

        self.analytics_cancel_btn = QPushButton("Cancel")
        self.analytics_cancel_btn.setFixedWidth(80)
        self.analytics_cancel_btn.clicked.connect(self.cancel_nas_analytics)
        self.analytics_cancel_btn.hide()
    
        controls_layout.addStretch()
        controls_layout.addWidget(self.analytics_status)
        controls_layout.addWidget(self.analytics_cancel_btn)
        controls_layout.addWidget(self.analytics_sync_btn)
    
        header_layout.addLayout(titles_layout)
        header_layout.addLayout(controls_layout)
        layout.addLayout(header_layout)

        # KPI Cards (Grid)
        grid = QGridLayout()
        grid.setSpacing(16)
    
        def make_card(title, value, color="#0038A8"):
            frame = QFrame()
            frame.setStyleSheet(f"background: white; border-radius: 8px; border: 1px solid #e0e0e0;")
            flayout = QVBoxLayout(frame)
            flayout.setContentsMargins(16, 16, 16, 16)
            t_lbl = QLabel(title)
            t_lbl.setStyleSheet("color: #666; font-size: 12px; font-weight: bold; border: none;")
            v_lbl = QLabel(str(value))
            v_lbl.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: bold; border: none;")
            flayout.addWidget(t_lbl)
            flayout.addWidget(v_lbl)
            return frame, v_lbl

        f1, self.kpi_unique = make_card("Total Unique Packets", "0", "#155724")
        f2, self.kpi_kits = make_card("Registration Kits", "0", "#0038A8")
        f3, self.kpi_nas1 = make_card("NAS1 Packets", "0", "#0038A8")
        f4, self.kpi_nas2 = make_card("NAS2 Packets", "0", "#0038A8")
        f5, self.kpi_dups = make_card("Duplicate Packets", "0", "#856404")
        f6, self.kpi_mismatch = make_card("Mismatched Kits", "0", "#721c24")
    
        grid.addWidget(f1, 0, 0)
        grid.addWidget(f2, 0, 1)
        grid.addWidget(f3, 0, 2)
        grid.addWidget(f4, 1, 0)
        grid.addWidget(f5, 1, 1)
        grid.addWidget(f6, 1, 2)
        layout.addLayout(grid)

        # Filter / Search Bar
        filter_layout = QHBoxLayout()
        self.analytics_search = QLineEdit()
        self.analytics_search.setPlaceholderText("Search Registration Kit (e.g. PRO-LPT-001)")
        self.analytics_search.textChanged.connect(self.filter_analytics_table)
    
        self.analytics_filter = QComboBox()
        self.analytics_filter.addItems(["All Status", "Complete", "Mismatch", "NAS1 Only", "NAS2 Only", "Empty Folder"])
        self.analytics_filter.currentTextChanged.connect(self.filter_analytics_table)
    
        filter_layout.addWidget(self.analytics_search, stretch=2)
        filter_layout.addWidget(self.analytics_filter, stretch=1)
        layout.addLayout(filter_layout)

        # Table
        self.analytics_table = QTableWidget(0, 7)
        self.analytics_table.setHorizontalHeaderLabels([
            "Registration Kit", "NAS1 Packets", "NAS2 Packets", 
            "Unique Packets", "Duplicates", "Source", "Status"
        ])
        self.analytics_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.analytics_table.setSortingEnabled(True)
        self.analytics_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.analytics_table.verticalHeader().setVisible(False)
    
        self.analytics_progress = QProgressBar()
        self.analytics_progress.setTextVisible(True)
        self.analytics_progress.setValue(0)
        self.analytics_progress.setMaximum(1)
        self.analytics_progress.hide()
        layout.addWidget(self.analytics_progress)

        layout.addWidget(self.analytics_table, stretch=1)
    
        # Internal state for tracking row items by kit name
        self.analytics_data = {}
        return page

    def filter_analytics_table(self):
        search_text = self.analytics_search.text().lower()
        status_filter = self.analytics_filter.currentText()
    
        for row in range(self.analytics_table.rowCount()):
            kit_item = self.analytics_table.item(row, 0)
            status_item = self.analytics_table.item(row, 6)
            if not kit_item or not status_item:
                continue
            
            kit = kit_item.text().lower()
            status = status_item.text()
        
            match_search = search_text in kit
            match_status = (status_filter == "All Status" or status_filter == status)
        
            self.analytics_table.setRowHidden(row, not (match_search and match_status))

    def cancel_nas_analytics(self):
        self.analytics_cancel_event.set()
        self.analytics_status.setText("Cancelling...")
        self.analytics_cancel_btn.setEnabled(False)

    def sync_nas_analytics(self):
        configs = []
        for nas_name in ("NAS1", "NAS2"):
            try:
                config = self.nas_config(nas_name)
                config["_root"] = normalize_remote_path(self.analytics_base_scan_dir.text() or "/Misamis Oriental")
                config["_label"] = nas_name
                configs.append(config)
            except Exception:
                pass

        if not configs:
            QMessageBox.warning(
                self,
                "NAS Analytics",
                "NAS credentials are not configured or missing.",
            )
            return

        self.analytics_sync_btn.setEnabled(False)
        self.analytics_sync_btn.hide()
        self.analytics_cancel_btn.setEnabled(True)
        self.analytics_cancel_btn.show()

        self.analytics_progress.setMinimum(0)
        self.analytics_progress.setMaximum(0)
        self.analytics_progress.setFormat("Scanning...")
        self.analytics_progress.show()

        self.analytics_status.setText("Scanning NAS targets in parallel...")
        self.analytics_table.setRowCount(0)
        self.analytics_data.clear()
        
        # Extract UI values safely before background thread
        chunk_size = self.chunk_size_mb.value()
    
        # Reset KPIs
        for kpi in [self.kpi_unique, self.kpi_kits, self.kpi_nas1, self.kpi_nas2, self.kpi_dups, self.kpi_mismatch]:
            kpi.setText("0")
        
        self.analytics_cancel_event.clear()
    
        # Global state for background workers
        global_merged = {}
        global_lock = threading.Lock()
    
        def make_folder_callback(nas_label):
            def callback(folder_name, folder_packets, running_unique_total):
                with global_lock:
                    if folder_name not in global_merged:
                        global_merged[folder_name] = {"NAS1": set(), "NAS2": set()}
                    global_merged[folder_name][nas_label] = set(folder_packets)
                
                    # Compute stats for this folder
                    n1 = len(global_merged[folder_name]["NAS1"])
                    n2 = len(global_merged[folder_name]["NAS2"])
                    u = len(global_merged[folder_name]["NAS1"] | global_merged[folder_name]["NAS2"])
                    d = len(global_merged[folder_name]["NAS1"] & global_merged[folder_name]["NAS2"])
                
                    if n1 > 0 and n2 > 0:
                        src = "NAS1 + NAS2"
                        status = "Complete" if n1 == n2 and u == n1 else "Mismatch"
                    elif n1 > 0:
                        src = "NAS1 Only"
                        status = "NAS1 Only"
                    elif n2 > 0:
                        src = "NAS2 Only"
                        status = "NAS2 Only"
                    else:
                        src = "Empty"
                        status = "Empty Folder"
                    
                    # Calculate global totals
                    tot_u = set()
                    tot_n1 = 0
                    tot_n2 = 0
                    tot_d = 0
                    tot_mm = 0
                
                    for f, data in global_merged.items():
                        fs1 = data["NAS1"]
                        fs2 = data["NAS2"]
                        tot_n1 += len(fs1)
                        tot_n2 += len(fs2)
                        tot_u.update(fs1 | fs2)
                        tot_d += len(fs1 & fs2)
                    
                        cn1 = len(fs1)
                        cn2 = len(fs2)
                        cu = len(fs1 | fs2)
                        if (cn1 > 0 and cn2 > 0) and (cn1 != cn2 or cu != cn1):
                            tot_mm += 1

                    stats = {
                        "f": folder_name,
                        "n1": n1, "n2": n2, "u": u, "d": d, "src": src, "status": status,
                        "tot_kits": len(global_merged),
                        "tot_u": len(tot_u),
                        "tot_n1": tot_n1,
                        "tot_n2": tot_n2,
                        "tot_d": tot_d,
                        "tot_mm": tot_mm
                    }
                
                def update(_s=stats):
                    self.analytics_table.setSortingEnabled(False)
                    row_idx = self.analytics_data.get(_s["f"])
                    if row_idx is None:
                        row_idx = self.analytics_table.rowCount()
                        self.analytics_table.insertRow(row_idx)
                        self.analytics_data[_s["f"]] = row_idx
                        self.analytics_table.setItem(row_idx, 0, readonly_item(_s["f"]))
                
                    def num_item(val):
                        it = QTableWidgetItem()
                        it.setData(Qt.DisplayRole, val)
                        it.setFlags(it.flags() & ~Qt.ItemIsEditable)
                        return it
                    
                    self.analytics_table.setItem(row_idx, 1, num_item(_s["n1"]))
                    self.analytics_table.setItem(row_idx, 2, num_item(_s["n2"]))
                    self.analytics_table.setItem(row_idx, 3, num_item(_s["u"]))
                    self.analytics_table.setItem(row_idx, 4, num_item(_s["d"]))
                    self.analytics_table.setItem(row_idx, 5, readonly_item(_s["src"]))
                
                    status_item = readonly_item(_s["status"])
                    if _s["status"] == "Mismatch":
                        status_item.setForeground(QColor("#721c24"))
                        status_item.setBackground(QColor("#f8d7da"))
                    elif _s["status"] == "Complete":
                        status_item.setForeground(QColor("#155724"))
                    self.analytics_table.setItem(row_idx, 6, status_item)
                
                    self.analytics_table.setSortingEnabled(True)
                
                    self.kpi_unique.setText(f"{_s['tot_u']:,}")
                    self.kpi_kits.setText(f"{_s['tot_kits']:,}")
                    self.kpi_nas1.setText(f"{_s['tot_n1']:,}")
                    self.kpi_nas2.setText(f"{_s['tot_n2']:,}")
                    self.kpi_dups.setText(f"{_s['tot_d']:,}")
                    self.kpi_mismatch.setText(f"{_s['tot_mm']:,}")
                
                    # Re-apply filter
                    self.filter_analytics_table()

                self.events.put({"type": "ui_call", "callback": update, "result": None})
            return callback

        def scan_nas(config):
            nas_label = config.get("_label", "Unknown")
            root = config.get("_root", "/")
            try:
                client_config = {k: v for k, v in config.items() if not k.startswith("_")}
                with NasClient(client_config, chunk_size) as client:
                    client.get_packet_analytics(
                        root=root,
                        cancel_event=self.analytics_cancel_event,
                        progress_callback=make_folder_callback(nas_label),
                    )
            except Exception as e:
                self.events.put({"type": "ui_call", "callback": lambda v=nas_label, err=str(e): (
                    self.analytics_status.setText(f"Error on {v}: {err}"),
                ), "result": None})

        def task():
            for config in configs:
                if self.analytics_cancel_event.is_set():
                    break
                
                nas_label = config.get("_label", "Unknown")
                self.events.put({"type": "ui_call", "callback": lambda v=nas_label: (
                    self.analytics_status.setText(f"Scanning {v}...")
                ), "result": None})
                
                scan_nas(config)
            return True

        def on_complete(data):
            self.analytics_sync_btn.setEnabled(True)
            self.analytics_sync_btn.show()
            self.analytics_cancel_btn.hide()
            self.analytics_progress.setMaximum(1)
            self.analytics_progress.setValue(1)
            self.analytics_progress.hide()
        
            if self.analytics_cancel_event.is_set():
                self.analytics_status.setText("Scan cancelled.")
            else:
                self.analytics_status.setText("Scan complete.")

        def on_error(err):
            self.analytics_sync_btn.setEnabled(True)
            self.analytics_sync_btn.show()
            self.analytics_cancel_btn.hide()
            self.analytics_progress.setMaximum(1)
            self.analytics_progress.setValue(0)
            self.analytics_progress.hide()
            self.analytics_status.setText("Error during scan.")
            self.background_error(err)

        self.run_background(task, on_complete, on_error)

    def build_settings_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        header = QLabel("Settings")
        header.setStyleSheet("font-size: 22px; font-weight: 800; color: #0038A8;")
        layout.addWidget(header)

        def scroll_tab(content):
            area = QScrollArea()
            area.setWidgetResizable(True)
            area.setWidget(content)
            return area

        tabs = QTabWidget()
        layout.addWidget(tabs, stretch=1)

        appearance_tab = QWidget()
        appearance_layout = QVBoxLayout(appearance_tab)
        appearance = QGroupBox("Appearance")
        appearance_form = QFormLayout(appearance)
        self.theme_select = QComboBox()
        self.theme_select.addItems(THEMES)
        self.theme_select.currentTextChanged.connect(self.change_theme)
        appearance_form.addRow("Theme", self.theme_select)
        appearance_layout.addWidget(appearance)
        appearance_layout.addStretch(1)
        tabs.addTab(scroll_tab(appearance_tab), "Appearance")

        self.nas_boxes = {
            "NAS1": CredentialBox("NAS1 - upload.philsys.gov.ph"),
            "NAS2": CredentialBox("NAS2 - 172.16.35.100"),
        }

        nas_tab = QWidget()
        nas_layout = QVBoxLayout(nas_tab)
        nas_hint = QLabel("Set NAS usernames and passwords here. Transfer directions use these saved NAS profiles.")
        nas_hint.setWordWrap(True)
        nas_layout.addWidget(nas_hint)
        nas_grid = QGridLayout()
        nas_grid.addWidget(self.nas_boxes["NAS1"], 0, 0)
        nas_grid.addWidget(self.nas_boxes["NAS2"], 0, 1)
        nas_grid.setColumnStretch(0, 1)
        nas_grid.setColumnStretch(1, 1)
        nas_layout.addLayout(nas_grid)
        
        self.analytics_base_scan_dir = QLineEdit()
        self.analytics_base_scan_dir.setPlaceholderText("e.g. /Misamis Oriental")
        nas_base_scan_layout = QHBoxLayout()
        nas_base_scan_layout.addWidget(QLabel("Analytics Base Scan Directory:"))
        nas_base_scan_layout.addWidget(self.analytics_base_scan_dir)
        nas_layout.addLayout(nas_base_scan_layout)

        for nas_name in ("NAS1", "NAS2"):
            button = QPushButton(f"Test {nas_name} Connection")
            button.clicked.connect(lambda _checked=False, name=nas_name: self.test_nas_connection(name))
            self.nas_boxes[nas_name].layout().addWidget(button, 4, 1, 1, 2)
        forget = QPushButton("Forget Saved Credentials")
        forget.setObjectName("DangerButton")
        forget.clicked.connect(self.forget_saved_credentials)
        nas_layout.addWidget(forget, alignment=Qt.AlignLeft)
        nas_layout.addStretch(1)
        tabs.addTab(scroll_tab(nas_tab), "NAS Credentials")

        province_tab = QWidget()
        province_layout = QVBoxLayout(province_tab)
        province_hint = QLabel(
            "Province NAS profiles are used by Packet Tracker and Matrix Restoration when a province NAS scope is selected."
        )
        province_hint.setWordWrap(True)
        province_layout.addWidget(province_hint)
        self.province_table = QTableWidget(0, 6)
        self.province_table.setHorizontalHeaderLabels(
            ["Province", "NAS Label", "Host/IP", "Port", "Default Root", "Username"]
        )
        self.province_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.province_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.province_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        province_layout.addWidget(self.province_table, stretch=1)
        province_buttons = QHBoxLayout()
        for label, slot in (
            ("Add Profile", self.add_province_profile),
            ("Edit Profile", self.edit_province_profile),
            ("Delete Profile", self.delete_province_profile),
            ("Test Connection", self.test_selected_province_profile),
        ):
            button = QPushButton(label)
            if label == "Add Profile":
                button.setObjectName("PrimaryButton")
            if label == "Delete Profile":
                button.setObjectName("DangerButton")
            button.clicked.connect(slot)
            province_buttons.addWidget(button)
        province_buttons.addStretch(1)
        province_layout.addLayout(province_buttons)
        tabs.addTab(scroll_tab(province_tab), "Province NAS Profiles")

        matrix_tab = QWidget()
        matrix_layout = QVBoxLayout(matrix_tab)
        matrix = QGroupBox("Matrix API")
        form = QFormLayout(matrix)
        self.matrix_api_base_url = QLineEdit()
        self.matrix_api_style = QComboBox()
        self.matrix_api_style.addItem("Redmine / Matrix issues API", "redmine")
        self.matrix_api_style.addItem("Generic bearer-token ticket API", "generic")
        self.matrix_api_token = QLineEdit()
        self.matrix_api_token.setEchoMode(QLineEdit.Password)
        self.matrix_show_token = QCheckBox("Show")
        self.matrix_save_token = QCheckBox("Save token securely")
        self.matrix_verify_ssl = QCheckBox("Verify SSL certificate")
        self.matrix_verify_ssl.setChecked(True)
        self.matrix_allow_self_signed.toggled.connect(self.sync_ssl_from_allow_self_signed)
        self.matrix_verify_ssl.toggled.connect(self.sync_ssl_from_verify)
        token_widget = QWidget()
        token_row = QHBoxLayout()
        token_row.setContentsMargins(0, 0, 0, 0)
        token_row.addWidget(self.matrix_api_token)
        token_row.addWidget(self.matrix_show_token)
        token_widget.setLayout(token_row)
        self.matrix_show_token.toggled.connect(
            lambda checked: self.matrix_api_token.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
        )
        self.matrix_user_full_name = QLineEdit()
        self.matrix_destination_root = QLineEdit(DEFAULT_MATRIX_DESTINATION_ROOT)
        form.addRow("API base URL", self.matrix_api_base_url)
        form.addRow("API type", self.matrix_api_style)
        form.addRow("API token/key", token_widget)
        form.addRow("", self.matrix_save_token)
        form.addRow("", self.matrix_verify_ssl)
        form.addRow("Assignee/login", self.matrix_user_full_name)
        form.addRow("Destination root", self.matrix_destination_root)
        matrix_layout.addWidget(matrix)
        test_matrix = QPushButton("Test Matrix API Connection")
        test_matrix.clicked.connect(self.test_matrix_connection)
        matrix_layout.addWidget(test_matrix, alignment=Qt.AlignLeft)
        matrix_note = QLabel(
            "Use the API access key from My account. The Atom access key is for feeds, not ticket API requests."
        )
        matrix_note.setWordWrap(True)
        matrix_layout.addWidget(matrix_note)
        matrix_layout.addStretch(1)
        tabs.addTab(scroll_tab(matrix_tab), "Matrix API")

        advanced_tab = QWidget()
        advanced_layout_root = QVBoxLayout(advanced_tab)
        advanced_note = QLabel(
            "Only change these endpoint templates when the Matrix API paths are confirmed. Wrong templates will make Matrix Sync fail safely."
        )
        advanced_note.setWordWrap(True)
        advanced_layout_root.addWidget(advanced_note)
        advanced = QGroupBox("Matrix Endpoint Templates")
        advanced_layout = QFormLayout(advanced)
        self.matrix_endpoint_assigned_tickets = QLineEdit()
        self.matrix_endpoint_ticket_comments = QLineEdit()
        self.matrix_endpoint_update_assignee = QLineEdit()
        self.matrix_endpoint_update_due_date = QLineEdit()
        self.matrix_endpoint_post_comment = QLineEdit()
        advanced_layout.addRow("Assigned tickets", self.matrix_endpoint_assigned_tickets)
        advanced_layout.addRow("Ticket comments", self.matrix_endpoint_ticket_comments)
        advanced_layout.addRow("Update assignee", self.matrix_endpoint_update_assignee)
        advanced_layout.addRow("Update due date", self.matrix_endpoint_update_due_date)
        advanced_layout.addRow("Post comment", self.matrix_endpoint_post_comment)
        advanced_layout_root.addWidget(advanced)
        redmine_defaults = QPushButton("Use Redmine Defaults")
        redmine_defaults.clicked.connect(self.reset_matrix_endpoints_to_redmine)
        advanced_layout_root.addWidget(redmine_defaults, alignment=Qt.AlignLeft)
        advanced_layout_root.addStretch(1)
        tabs.addTab(scroll_tab(advanced_tab), "Advanced")

        logs_tab = QWidget()
        logs_layout = QVBoxLayout(logs_tab)
        log_box = QGroupBox("Log Location")
        log_layout = QHBoxLayout(log_box)
        self.log_location = QLineEdit(str(LOG_DIR))
        self.log_location.setReadOnly(True)
        open_logs_button = QPushButton("Open Logs")
        open_logs_button.clicked.connect(self.open_logs)
        log_layout.addWidget(self.log_location)
        log_layout.addWidget(open_logs_button)
        logs_layout.addWidget(log_box)
        logs_layout.addStretch(1)
        tabs.addTab(scroll_tab(logs_tab), "Logs")

        save_button = QPushButton("Save Settings")
        save_button.clicked.connect(self.save_current_settings)
        layout.addWidget(save_button, alignment=Qt.AlignLeft)
        return page

    def build_logs_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        header = QLabel("Logs")
        header.setStyleSheet("font-size: 22px; font-weight: 800; color: #0038A8;")
        layout.addWidget(header)

        filters = QHBoxLayout()
        self.log_filter_info = QCheckBox("Info")
        self.log_filter_warning = QCheckBox("Warning")
        self.log_filter_error = QCheckBox("Error")
        self.log_filter_transfer = QCheckBox("Transfer")
        self.log_filter_matrix = QCheckBox("Matrix API")
        self.log_filter_packet = QCheckBox("Packet Search")
        for checkbox in (
            self.log_filter_info,
            self.log_filter_warning,
            self.log_filter_error,
            self.log_filter_transfer,
            self.log_filter_matrix,
            self.log_filter_packet,
        ):
            checkbox.setChecked(True)
            checkbox.toggled.connect(self.refresh_logs)
            filters.addWidget(checkbox)
        filters.addStretch(1)
        layout.addLayout(filters)

        button_row = QHBoxLayout()
        refresh = QPushButton("Refresh Logs")
        copy_selected = QPushButton("Copy Selected Log")
        clear_visible = QPushButton("Clear Visible Logs")
        export = QPushButton("Export Logs")
        open_folder = QPushButton("Open Logs Folder")
        refresh.clicked.connect(self.refresh_logs)
        copy_selected.clicked.connect(self.copy_selected_logs)
        clear_visible.clicked.connect(self.clear_visible_logs)
        export.clicked.connect(self.export_logs)
        open_folder.clicked.connect(self.open_logs)
        button_row.addWidget(refresh)
        button_row.addWidget(copy_selected)
        button_row.addWidget(clear_visible)
        button_row.addWidget(export)
        button_row.addWidget(open_folder)
        button_row.addStretch(1)
        layout.addLayout(button_row)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("font-family: Consolas, 'Courier New', monospace;")
        layout.addWidget(self.log_view, stretch=1)
        return page

    def load_settings_into_ui(self):
        index = self.direction.findData(self.settings["direction"])
        self.direction.setCurrentIndex(index if index >= 0 else 0)
        operation_index = self.operation.findData(self.settings["operation"])
        self.operation.setCurrentIndex(operation_index if operation_index >= 0 else 0)
        self.source_path.setText(self.settings["source_path"])
        self.destination_path.setText(self.settings["destination_path"])
        self.verification.setCurrentText(self.settings["verification_mode"])
        self.skip_verified.setChecked(self.settings["skip_verified_on_resume"])
        self.retry_limit.setValue(int(self.settings["retry_limit"]))
        self.parallel_workers.setValue(int(self.settings.get("parallel_workers", DEFAULT_PARALLEL_WORKERS)))
        self.chunk_size_mb.setValue(int(self.settings.get("chunk_size_mb", DEFAULT_CHUNK_SIZE_MB)))
        self.analytics_base_scan_dir.setText(self.settings.get("analytics_base_scan_dir", "/Misamis Oriental"))
        self.packet_search_root.setText(self.settings.get("packet_search_root", "/"))
        self.packet_target_nas.setCurrentText(self.settings.get("packet_target_nas", "NAS1"))
        self.packet_target_folder.setText(self.settings.get("packet_target_folder", DEFAULT_MATRIX_DESTINATION_ROOT))
        self.refresh_province_profile_controls()
        self.packet_province_profile.setEnabled(self.packet_scope.currentText() == "Province NAS")
        self.matrix_province_profile.setEnabled(self.matrix_scope.currentText() == "Selected Province NAS")
        if hasattr(self, "theme_select"):
            self.theme_select.setCurrentText(self.settings.get("theme", "System"))
        self.matrix_api_base_url.setText(self.settings.get("matrix_api_base_url", "https://matrix.philsys.gov.ph"))
        api_style_index = self.matrix_api_style.findData(self.settings.get("matrix_api_style", "redmine"))
        self.matrix_api_style.setCurrentIndex(api_style_index if api_style_index >= 0 else 0)
        self.matrix_user_full_name.setText(self.settings.get("matrix_user_full_name", ""))
        self.matrix_ticket_numbers.setText(self.settings.get("matrix_ticket_numbers", ""))
        self.matrix_destination_root.setText(
            self.settings.get("matrix_destination_root", DEFAULT_MATRIX_DESTINATION_ROOT)
        )
        self.matrix_save_token.setChecked(bool(self.settings.get("matrix_save_token", False)))
        matrix_verify_ssl = bool(self.settings.get("matrix_verify_ssl", True))
        self.matrix_verify_ssl.setChecked(matrix_verify_ssl)
        self.matrix_allow_self_signed.setChecked(not matrix_verify_ssl)
        self.matrix_endpoint_assigned_tickets.setText(self.settings.get("matrix_endpoint_assigned_tickets", ""))
        self.matrix_endpoint_ticket_comments.setText(self.settings.get("matrix_endpoint_ticket_comments", ""))
        self.matrix_endpoint_update_assignee.setText(self.settings.get("matrix_endpoint_update_assignee", ""))
        self.matrix_endpoint_update_due_date.setText(self.settings.get("matrix_endpoint_update_due_date", ""))
        self.matrix_endpoint_post_comment.setText(self.settings.get("matrix_endpoint_post_comment", ""))

        nas1_username = self.settings.get("nas1_username") or self.settings.get("source_username", "")
        nas2_username = self.settings.get("nas2_username") or self.settings.get("destination_username", "")
        self.nas_boxes["NAS1"].username.setText(nas1_username)
        self.nas_boxes["NAS2"].username.setText(nas2_username)
        self.nas_boxes["NAS1"].save_credentials.setChecked(
            bool(self.settings.get("nas1_save_credentials") or self.settings.get("source_save_credentials"))
        )
        self.nas_boxes["NAS2"].save_credentials.setChecked(
            bool(self.settings.get("nas2_save_credentials") or self.settings.get("destination_save_credentials"))
        )

    def load_saved_credentials(self):
        for nas_name, box in self.nas_boxes.items():
            username = box.username.text().strip()
            if not username or not box.save_credentials.isChecked():
                continue
            password = self.credentials.get_password("nas", nas_name, username)
            if not password:
                password = self.credentials.get_password("source", nas_name, username)
            if not password:
                password = self.credentials.get_password("destination", nas_name, username)
            box.password.setText(password)

        if self.matrix_save_token.isChecked():
            self.matrix_api_token.setText(self.credentials.get_secret("matrix_api_token"))

    def save_current_settings(self):
        self.settings.update(
            {
                "direction": self.current_direction(),
                "operation": self.current_operation(),
                "source_path": normalize_remote_path(self.source_path.text()),
                "destination_path": normalize_remote_path(self.destination_path.text()),
                "source_username": self.nas_boxes["NAS1"].username.text().strip(),
                "destination_username": self.nas_boxes["NAS2"].username.text().strip(),
                "source_save_credentials": self.nas_boxes["NAS1"].save_credentials.isChecked(),
                "destination_save_credentials": self.nas_boxes["NAS2"].save_credentials.isChecked(),
                "nas1_username": self.nas_boxes["NAS1"].username.text().strip(),
                "nas2_username": self.nas_boxes["NAS2"].username.text().strip(),
                "nas1_save_credentials": self.nas_boxes["NAS1"].save_credentials.isChecked(),
                "nas2_save_credentials": self.nas_boxes["NAS2"].save_credentials.isChecked(),
                "verification_mode": self.verification.currentText(),
                "skip_verified_on_resume": self.skip_verified.isChecked(),
                "retry_limit": self.retry_limit.value(),
                "parallel_workers": self.parallel_workers.value(),
                "chunk_size_mb": self.chunk_size_mb.value(),
                "analytics_base_scan_dir": normalize_remote_path(self.analytics_base_scan_dir.text() or "/Misamis Oriental"),
                "packet_search_root": normalize_remote_path(self.packet_search_root.text()),
                "packet_target_nas": self.packet_target_nas.currentText(),
                "packet_target_folder": normalize_remote_path(self.packet_target_folder.text()),
                "theme": self.theme_select.currentText(),
                "packet_province_profile_id": self.selected_packet_province_profile_id(),
                "matrix_province_profile_id": self.selected_matrix_province_profile_id(),
                "matrix_api_base_url": self.matrix_api_base_url.text().strip(),
                "matrix_api_style": self.current_matrix_api_style(),
                "matrix_user_full_name": self.matrix_user_full_name.text().strip(),
                "matrix_ticket_numbers": self.matrix_ticket_numbers.text().strip(),
                "matrix_destination_root": normalize_remote_path(self.matrix_destination_root.text()),
                "matrix_save_token": self.matrix_save_token.isChecked(),
                "matrix_verify_ssl": self.current_matrix_verify_ssl(),
                "matrix_endpoint_assigned_tickets": self.matrix_endpoint_assigned_tickets.text().strip(),
                "matrix_endpoint_ticket_comments": self.matrix_endpoint_ticket_comments.text().strip(),
                "matrix_endpoint_update_assignee": self.matrix_endpoint_update_assignee.text().strip(),
                "matrix_endpoint_update_due_date": self.matrix_endpoint_update_due_date.text().strip(),
                "matrix_endpoint_post_comment": self.matrix_endpoint_post_comment.text().strip(),
            }
        )

        for nas_name, box in self.nas_boxes.items():
            username = box.username.text().strip()
            if box.save_credentials.isChecked():
                self.credentials.save_password("nas", nas_name, username, box.password.text())
            else:
                self.credentials.delete_password("nas", nas_name, username)

        if self.matrix_save_token.isChecked():
            self.credentials.save_secret("matrix_api_token", self.matrix_api_token.text())
        else:
            self.credentials.delete_secret("matrix_api_token")

        save_settings(self.settings)
        self.log_action("INFO", "Settings", "Settings saved")
        QMessageBox.information(self, "Settings Saved", "Settings were saved.")

    def current_direction(self):
        return self.direction.currentData() or self.direction.currentText()

    def current_operation(self):
        return self.operation.currentData() or self.operation.currentText().strip().lower()

    def nas_config(self, nas_name):
        endpoint = endpoint_by_name(nas_name)
        box = self.nas_boxes[nas_name]
        username = box.username.text().strip()
        password = box.password.text()
        if not username or not password:
            raise ValueError(f"{nas_name} username and password are required.")
        return {**endpoint, "username": username, "password": password}

    def change_theme(self, theme_name):
        self.settings["theme"] = theme_name
        self.apply_theme(theme_name)

    def province_profiles(self):
        profiles = self.settings.setdefault("province_profiles", [])
        return profiles if isinstance(profiles, list) else []

    def province_profile_by_id(self, profile_id):
        for profile in self.province_profiles():
            if profile.get("id") == profile_id:
                return profile
        return None

    def province_profile_label(self, profile):
        if not profile:
            return ""
        province = profile.get("province") or "Province"
        label = profile.get("label") or profile.get("host") or "NAS"
        return f"{province} - {label}"

    def refresh_profile_combo(self, combo, selected_id):
        combo.blockSignals(True)
        combo.clear()
        combo.addItem("Select province NAS profile", "")
        for profile in self.province_profiles():
            combo.addItem(self.province_profile_label(profile), profile.get("id", ""))
        index = combo.findData(selected_id or "")
        combo.setCurrentIndex(index if index >= 0 else 0)
        combo.blockSignals(False)

    def refresh_province_profile_controls(self):
        self.refresh_profile_combo(
            self.packet_province_profile,
            self.settings.get("packet_province_profile_id", ""),
        )
        self.refresh_profile_combo(
            self.matrix_province_profile,
            self.settings.get("matrix_province_profile_id", ""),
        )
        self.render_province_profiles()

    def render_province_profiles(self):
        if not hasattr(self, "province_table"):
            return
        self.province_table.setSortingEnabled(False)
        self.province_table.setRowCount(0)
        for profile in self.province_profiles():
            row = self.province_table.rowCount()
            self.province_table.insertRow(row)
            values = [
                profile.get("province", ""),
                profile.get("label", ""),
                profile.get("host", ""),
                str(profile.get("port") or ""),
                profile.get("root", "/"),
                profile.get("username", ""),
            ]
            for column, value in enumerate(values):
                item = readonly_item(value)
                if column == 0:
                    item.setData(Qt.UserRole, profile.get("id", ""))
                self.province_table.setItem(row, column, item)
        self.province_table.setSortingEnabled(True)

    def selected_province_table_profile_id(self):
        rows = sorted({index.row() for index in self.province_table.selectedIndexes()})
        if not rows:
            return ""
        item = self.province_table.item(rows[0], 0)
        return item.data(Qt.UserRole) if item else ""

    def selected_packet_province_profile_id(self):
        return self.packet_province_profile.currentData() or ""

    def selected_matrix_province_profile_id(self):
        return self.matrix_province_profile.currentData() or ""

    def province_nas_config(self, profile_id):
        profile = self.province_profile_by_id(profile_id)
        if not profile:
            raise ValueError("Select a valid province NAS profile.")
        username = (profile.get("username") or "").strip()
        password = self.credentials.get_password("province", profile_id, username)
        if not profile.get("host") or not username or not password:
            raise ValueError(f"{self.province_profile_label(profile)} host, username, and password are required.")
        return {
            "name": f"PROFILE:{profile_id}",
            "profile_name": self.province_profile_label(profile),
            "host": profile.get("host", "").strip(),
            "port": int(profile.get("port") or 2222),
            "username": username,
            "password": password,
        }

    def source_display_name(self, source_name):
        if str(source_name).startswith("PROFILE:"):
            profile = self.province_profile_by_id(str(source_name).split(":", 1)[1])
            return self.province_profile_label(profile) if profile else "Province NAS"
        return source_name

    def config_for_source(self, source_name):
        source_name = str(source_name)
        if source_name.startswith("PROFILE:"):
            return self.province_nas_config(source_name.split(":", 1)[1])
        return self.nas_config(source_name)

    def search_configs_for_scope(self, scope, profile_id=""):
        if scope == "Both NAS":
            return [(name, self.nas_config(name), "/") for name in ("NAS1", "NAS2")]
        if scope.startswith("NAS1"):
            return [("NAS1", self.nas_config("NAS1"), "/")]
        if scope.startswith("NAS2"):
            return [("NAS2", self.nas_config("NAS2"), "/")]
        if "Province" in scope:
            profile = self.province_profile_by_id(profile_id)
            config = self.province_nas_config(profile_id)
            return [(config["name"], config, normalize_remote_path(profile.get("root", "/")))]
        raise ValueError(f"Unsupported NAS search scope: {scope}")

    def add_province_profile(self):
        dialog = ProvinceProfileDialog(self)
        if dialog.exec() != QDialog.Accepted:
            return
        profile, password = dialog.profile_data()
        if not profile.get("province") or not profile.get("host") or not profile.get("username"):
            QMessageBox.warning(self, "Province NAS Profile", "Province, host, and username are required.")
            return
        self.province_profiles().append(profile)
        if password:
            self.credentials.save_password("province", profile["id"], profile["username"], password)
        save_settings(self.settings)
        self.refresh_province_profile_controls()

    def edit_province_profile(self):
        profile_id = self.selected_province_table_profile_id()
        profile = self.province_profile_by_id(profile_id)
        if not profile:
            QMessageBox.warning(self, "Province NAS Profile", "Select a province profile to edit.")
            return
        old_username = profile.get("username", "")
        dialog = ProvinceProfileDialog(self, profile)
        if dialog.exec() != QDialog.Accepted:
            return
        updated, password = dialog.profile_data(existing_id=profile_id)
        if not updated.get("province") or not updated.get("host") or not updated.get("username"):
            QMessageBox.warning(self, "Province NAS Profile", "Province, host, and username are required.")
            return
        profile.update(updated)
        if old_username and old_username != updated["username"]:
            self.credentials.delete_password("province", profile_id, old_username)
        if password:
            self.credentials.save_password("province", profile_id, updated["username"], password)
        save_settings(self.settings)
        self.refresh_province_profile_controls()

    def delete_province_profile(self):
        profile_id = self.selected_province_table_profile_id()
        profile = self.province_profile_by_id(profile_id)
        if not profile:
            QMessageBox.warning(self, "Province NAS Profile", "Select a province profile to delete.")
            return
        if QMessageBox.question(self, "Delete Province Profile", f"Delete {self.province_profile_label(profile)}?") != QMessageBox.Yes:
            return
        self.credentials.delete_password("province", profile_id, profile.get("username", ""))
        self.settings["province_profiles"] = [
            item for item in self.province_profiles() if item.get("id") != profile_id
        ]
        if self.settings.get("packet_province_profile_id") == profile_id:
            self.settings["packet_province_profile_id"] = ""
        if self.settings.get("matrix_province_profile_id") == profile_id:
            self.settings["matrix_province_profile_id"] = ""
        save_settings(self.settings)
        self.refresh_province_profile_controls()

    def test_selected_province_profile(self):
        profile_id = self.selected_province_table_profile_id()
        profile = self.province_profile_by_id(profile_id)
        if not profile:
            QMessageBox.warning(self, "Province NAS Profile", "Select a province profile to test.")
            return

        def task():
            with NasClient(self.province_nas_config(profile_id), self.chunk_size_mb.value()) as client:
                client.test_connection()
            return self.province_profile_label(profile)

        self.run_background(
            task,
            lambda label: QMessageBox.information(self, "Connection OK", f"{label} connected successfully."),
            self.background_error,
        )

    def matrix_endpoints(self):
        return {
            "assigned_tickets": self.matrix_endpoint_assigned_tickets.text().strip(),
            "ticket_comments": self.matrix_endpoint_ticket_comments.text().strip(),
            "update_assignee": self.matrix_endpoint_update_assignee.text().strip(),
            "update_due_date": self.matrix_endpoint_update_due_date.text().strip(),
            "post_comment": self.matrix_endpoint_post_comment.text().strip(),
        }

    def matrix_client(self):
        if not self.matrix_api_base_url.text().strip():
            raise ValueError("Matrix API base URL is required.")
        if not self.matrix_api_token.text():
            raise ValueError("Matrix API token/key is required.")
        return self.build_matrix_client(self.current_matrix_verify_ssl())

    def build_matrix_client(self, verify_ssl):
        return MatrixApiClient(
            self.matrix_api_base_url.text().strip(),
            self.matrix_api_token.text(),
            self.matrix_endpoints(),
            verify_ssl=verify_ssl,
            api_style=self.current_matrix_api_style(),
        )

    def current_matrix_api_style(self):
        return self.matrix_api_style.currentData() or "redmine"

    def reset_matrix_endpoints_to_redmine(self):
        self.matrix_api_style.setCurrentIndex(0)
        self.matrix_endpoint_assigned_tickets.setText(REDMINE_MATRIX_ENDPOINTS["matrix_endpoint_assigned_tickets"])
        self.matrix_endpoint_ticket_comments.setText(REDMINE_MATRIX_ENDPOINTS["matrix_endpoint_ticket_comments"])
        self.matrix_endpoint_update_assignee.setText(REDMINE_MATRIX_ENDPOINTS["matrix_endpoint_update_assignee"])
        self.matrix_endpoint_update_due_date.setText(REDMINE_MATRIX_ENDPOINTS["matrix_endpoint_update_due_date"])
        self.matrix_endpoint_post_comment.setText(REDMINE_MATRIX_ENDPOINTS["matrix_endpoint_post_comment"])
        self.matrix_status.setText("Redmine Matrix endpoint defaults restored.")

    def current_matrix_verify_ssl(self):
        return not self.matrix_allow_self_signed.isChecked()

    def sync_ssl_from_allow_self_signed(self, checked):
        if hasattr(self, "matrix_verify_ssl") and self.matrix_verify_ssl.isChecked() == checked:
            self.matrix_verify_ssl.blockSignals(True)
            self.matrix_verify_ssl.setChecked(not checked)
            self.matrix_verify_ssl.blockSignals(False)

    def sync_ssl_from_verify(self, checked):
        if hasattr(self, "matrix_allow_self_signed") and self.matrix_allow_self_signed.isChecked() == checked:
            self.matrix_allow_self_signed.blockSignals(True)
            self.matrix_allow_self_signed.setChecked(not checked)
            self.matrix_allow_self_signed.blockSignals(False)

    def enable_internal_matrix_certificate_mode(self, _result=None):
        self.matrix_allow_self_signed.setChecked(True)
        self.settings["matrix_verify_ssl"] = False
        save_settings(self.settings)
        self.matrix_status.setText("Internal/self-signed certificate detected. Retrying Matrix API request...")
        self.log_action(
            "WARNING",
            "Matrix API",
            "Certificate verification failed; retrying with internal/self-signed certificate mode.",
        )

    def update_direction_labels(self):
        source, destination = direction_endpoints(self.current_direction())
        self.source_card_label.setText(f"{source['name']} - {source['host']}")
        self.source_host_label.setText(source["host"])
        self.destination_card_label.setText(f"{destination['name']} - {destination['host']}")
        self.destination_host_label.setText(destination["host"])
        self.source_card.setTitle("Source NAS")
        self.destination_card.setTitle("Destination NAS")

    def source_endpoint_name(self):
        source, _destination = direction_endpoints(self.current_direction())
        return source["name"]

    def destination_endpoint_name(self):
        _source, destination = direction_endpoints(self.current_direction())
        return destination["name"]

    def build_params(self, retry_failed_only=False, verify_existing_only=False):
        source, destination = direction_endpoints(self.current_direction())
        return {
            "direction": self.current_direction(),
            "operation": self.current_operation(),
            "source_path": normalize_remote_path(self.source_path.text()),
            "destination_path": normalize_remote_path(self.destination_path.text()),
            "source_config": self.nas_config(source["name"]),
            "destination_config": self.nas_config(destination["name"]),
            "verification_mode": self.verification.currentText(),
            "skip_verified_on_resume": self.skip_verified.isChecked(),
            "retry_limit": self.retry_limit.value(),
            "parallel_workers": self.parallel_workers.value(),
            "chunk_size_mb": self.chunk_size_mb.value(),
            "retry_failed_only": retry_failed_only,
            "verify_existing_only": verify_existing_only,
        }

    def confirm_move(self):
        if self.current_operation() != "move":
            return True

        return (
            QMessageBox.question(
                self,
                "Confirm Move",
                "Move mode deletes each source file after it is successfully transferred and finalized on the destination. Continue?",
            )
            == QMessageBox.Yes
        )

    def start_transfer(self, retry_failed_only=False, verify_existing_only=False):
        if self.worker_thread and self.worker_thread.is_alive():
            QMessageBox.warning(self, "Transfer Running", "A transfer is already running.")
            return

        try:
            params = self.build_params(retry_failed_only, verify_existing_only)
        except Exception as error:
            QMessageBox.critical(self, "Invalid Settings", str(error))
            return

        if not verify_existing_only and not self.confirm_move():
            return

        self.save_settings_silent()
        self.pause_event.set()
        self.cancel_event.clear()
        self.events = queue.Queue()
        self.app_logger, self.current_log_file = create_logger()
        self.log_action("INFO", "Transfer", "Transfer started")

        engine = TransferEngine(
            params=params,
            state_db=self.db,
            logger=self.app_logger,
            event_queue=self.events,
            pause_event=self.pause_event,
            cancel_event=self.cancel_event,
        )
        self.current_engine = engine
        self.current_job_key = engine.job_key
        self.table.setRowCount(0)
        self.table_rows.clear()
        set_badge(self.status, "Running")
        set_badge(self.source_status, "Testing")
        set_badge(self.destination_status, "Testing")
        self.current_file.setText("-")
        self.file_progress.setValue(0)
        self.overall_progress.setValue(0)
        self.last_data_done = 0
        self.last_speed_time = time.monotonic()
        self.average_start_time = time.monotonic()
        self.current_speed = 0

        self.worker_thread = threading.Thread(target=engine.run, daemon=True)
        self.worker_thread.start()

    def save_settings_silent(self):
        self.settings.update(
            {
                "direction": self.current_direction(),
                "operation": self.current_operation(),
                "source_path": normalize_remote_path(self.source_path.text()),
                "destination_path": normalize_remote_path(self.destination_path.text()),
                "verification_mode": self.verification.currentText(),
                "skip_verified_on_resume": self.skip_verified.isChecked(),
                "retry_limit": self.retry_limit.value(),
                "parallel_workers": self.parallel_workers.value(),
                "chunk_size_mb": self.chunk_size_mb.value(),
                "packet_search_root": normalize_remote_path(self.packet_search_root.text()),
                "packet_target_nas": self.packet_target_nas.currentText(),
                "packet_target_folder": normalize_remote_path(self.packet_target_folder.text()),
                "theme": self.theme_select.currentText(),
                "packet_province_profile_id": self.selected_packet_province_profile_id(),
                "matrix_province_profile_id": self.selected_matrix_province_profile_id(),
                "matrix_api_base_url": self.matrix_api_base_url.text().strip(),
                "matrix_api_style": self.current_matrix_api_style(),
                "matrix_user_full_name": self.matrix_user_full_name.text().strip(),
                "matrix_ticket_numbers": self.matrix_ticket_numbers.text().strip(),
                "matrix_destination_root": normalize_remote_path(self.matrix_destination_root.text()),
                "matrix_verify_ssl": self.current_matrix_verify_ssl(),
                "matrix_endpoint_assigned_tickets": self.matrix_endpoint_assigned_tickets.text().strip(),
                "matrix_endpoint_ticket_comments": self.matrix_endpoint_ticket_comments.text().strip(),
                "matrix_endpoint_update_assignee": self.matrix_endpoint_update_assignee.text().strip(),
                "matrix_endpoint_update_due_date": self.matrix_endpoint_update_due_date.text().strip(),
                "matrix_endpoint_post_comment": self.matrix_endpoint_post_comment.text().strip(),
            }
        )
        save_settings(self.settings)

    def pause_transfer(self):
        self.pause_event.clear()
        set_badge(self.status, "Paused")

    def resume_transfer(self):
        self.pause_event.set()
        set_badge(self.status, "Running")

    def cancel_transfer(self):
        if self.matrix_worker_thread and self.matrix_worker_thread.is_alive():
            self.matrix_cancel_event.set()
            self.matrix_status.setText("Cancelling Matrix packet search...")
            return

        if not (self.worker_thread and self.worker_thread.is_alive()):
            self.table.setRowCount(0)
            self.table_rows.clear()
            set_badge(self.status, "Ready")
            set_badge(self.source_status, "-")
            set_badge(self.destination_status, "-")
            self.current_file.setText("-")
            self.file_progress.setValue(0)
            self.overall_progress.setValue(0)
            for label in self.metric_labels.values():
                label.setText("-")
            return

        if QMessageBox.question(self, "Cancel Transfer", "Cancel the current transfer?") == QMessageBox.Yes:
            self.cancel_event.set()
            self.pause_event.set()
            if hasattr(self, "current_engine") and self.current_engine:
                self.current_engine.force_disconnect()

    def retry_failed(self):
        self.start_transfer(retry_failed_only=True)

    def verify_existing(self):
        self.start_transfer(verify_existing_only=True)

    def open_logs(self):
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        os.startfile(LOG_DIR)

    def open_destination_folder(self):
        destination = normalize_remote_path(self.destination_path.text())
        QApplication.clipboard().setText(destination)
        QMessageBox.information(
            self,
            "Destination Path",
            "The destination is an SFTP path. The path was copied to the clipboard.",
        )

    def test_nas_connection(self, nas_name):
        self.set_nas_badges(nas_name, "Testing")

        def task():
            config = self.nas_config(nas_name)
            with NasClient(config, self.chunk_size_mb.value()) as client:
                client.test_connection()
            return nas_name

        self.run_background(task, lambda name: self.set_nas_badges(name, "Connected"), self.nas_test_error(nas_name))

    def set_nas_badges(self, nas_name, text):
        if nas_name in self.nas_boxes:
            set_badge(self.nas_boxes[nas_name].status, text)
        if self.source_endpoint_name() == nas_name:
            set_badge(self.source_status, text)
        if self.destination_endpoint_name() == nas_name:
            set_badge(self.destination_status, text)

    def nas_test_error(self, nas_name):
        def handle(error):
            self.set_nas_badges(nas_name, "Error")
            self.background_error(error)

        return handle

    def test_matrix_connection(self):
        self.save_settings_silent()
        self.matrix_status.setText("Testing Matrix API connection...")

        def task():
            client = self.matrix_client()
            tickets = client.get_assigned_tickets(self.matrix_user_full_name.text().strip() or "me")
            return len(tickets)

        self.run_background(
            task,
            lambda count: self.matrix_status.setText(f"Matrix API connected. Returned {count} assigned ticket(s)."),
            self.background_error,
        )

    def forget_saved_credentials(self):
        for nas_name, box in self.nas_boxes.items():
            username = box.username.text().strip()
            self.credentials.delete_password("nas", nas_name, username)
            box.password.clear()
            box.save_credentials.setChecked(False)
        self.credentials.delete_secret("matrix_api_token")
        self.matrix_api_token.clear()
        self.matrix_save_token.setChecked(False)
        save_settings(self.settings)
        QMessageBox.information(self, "Credentials Removed", "Saved NAS passwords and Matrix token were removed.")

    def run_background(self, task, on_success=None, on_error=None):
        def wrapper():
            try:
                result = task()
                self.events.put({"type": "ui_call", "callback": on_success, "result": result})
            except Exception as error:
                self.events.put({"type": "ui_error", "callback": on_error, "error": error})

        threading.Thread(target=wrapper, daemon=True).start()

    def set_matrix_status(self, text):
        self.matrix_status.setText(str(text))

    def cancel_matrix_search(self):
        if self.matrix_worker_thread and self.matrix_worker_thread.is_alive():
            self.matrix_cancel_event.set()
            self.matrix_status.setText("Cancelling Matrix packet search...")

    def background_error(self, error):
        QMessageBox.critical(self, "Operation Failed", str(error))
        self.log_action("ERROR", "Background", str(error))

    def update_packet_count_preview(self):
        count = len(parse_packet_input(self.packet_input.toPlainText()))
        self.packet_count_label.setText(f"{count} packet ID{'s' if count != 1 else ''} detected.")

    def apply_packet_result_filter(self):
        text = self.packet_result_filter.text().strip().casefold()
        for row in range(self.packet_table.rowCount()):
            if not text:
                self.packet_table.setRowHidden(row, False)
                continue
            values = []
            for column in range(self.packet_table.columnCount()):
                item = self.packet_table.item(row, column)
                values.append(item.text().casefold() if item else "")
            self.packet_table.setRowHidden(row, text not in " ".join(values))

    def selected_packet_results(self):
        rows = [
            row
            for row in range(self.packet_table.rowCount())
            if self.packet_table.item(row, 0) and self.packet_table.item(row, 0).checkState() == Qt.Checked
        ]
        if not rows:
            rows = sorted({index.row() for index in self.packet_table.selectedIndexes()})
        results = []
        for row in rows:
            item = self.packet_table.item(row, 0)
            if not item:
                continue
            result_index = item.data(Qt.UserRole)
            if isinstance(result_index, int) and 0 <= result_index < len(self.packet_results):
                result = self.packet_results[result_index]
                if result.status == "Found":
                    results.append(result)
        return results

    def import_packet_list(self):
        path, _filter = QFileDialog.getOpenFileName(self, "Import Packet List", "", "Text or CSV (*.txt *.csv);;All Files (*.*)")
        if not path:
            return
        self.packet_input.setPlainText(Path(path).read_text(encoding="utf-8", errors="replace"))

    def search_packets(self):
        packet_ids = parse_packet_input(self.packet_input.toPlainText())
        if not packet_ids:
            QMessageBox.warning(self, "Packet Search", "Enter at least one packet ID.")
            return
        scope = self.packet_scope.currentText()
        root = normalize_remote_path(self.packet_search_root.text())
        try:
            search_configs = self.search_configs_for_scope(scope, self.selected_packet_province_profile_id())
        except Exception as error:
            QMessageBox.critical(self, "Packet Search", str(error))
            return
        self.save_settings_silent()
        self.packet_status.setText("Searching packets...")
        self.packet_table.setRowCount(0)
        self.packet_results.clear()
        self.log_action("INFO", "Packet Search", f"Searching {len(packet_ids)} packet ID(s) in {scope}")

        self.packet_cancel_event.clear()
        num_nas = len(search_configs)
        self.packet_progress.setMaximum(num_nas)
        self.packet_progress.setValue(0)

        def task():
            results = []
            machine_folder_by_packet = {
                packet_id: machine_folder_for_packet(packet_id)
                for packet_id in packet_ids
                if machine_folder_for_packet(packet_id)
            }
            unmapped_packet_ids = [packet_id for packet_id in packet_ids if packet_id not in machine_folder_by_packet]
            for nas_idx, (_source_name, config, default_root) in enumerate(search_configs, start=1):
                if self.packet_cancel_event.is_set():
                    break
                search_root = root if root != "/" else default_root
                self.events.put({"type": "ui_call", "callback": lambda v: self.packet_status.setText(f"Searching {_source_name}..."), "result": None})
                with NasClient(config, self.chunk_size_mb.value()) as client:
                    custom_unmapped = unmapped_packet_ids[:]
                    custom_machine_map = {}
                    
                    for pid, m_folder in machine_folder_by_packet.items():
                        if m_folder.casefold() in search_root.casefold():
                            custom_unmapped.append(pid)
                        else:
                            custom_machine_map[pid] = m_folder

                    if custom_machine_map:
                        results.extend(
                            client.search_packets_by_machine_folders(
                                list(custom_machine_map.keys()),
                                custom_machine_map,
                                root=search_root,
                                max_results_per_packet=1,
                                cancel_event=self.packet_cancel_event,
                            )
                        )
                    if custom_unmapped:
                        results.extend(client.search_packets(
                            custom_unmapped, 
                            search_root, 
                            cancel_event=self.packet_cancel_event,
                            max_results_per_packet=1,
                            stop_when_all_found=True
                        ))
                self.events.put({"type": "ui_call", "callback": lambda v: self.packet_progress.setValue(v), "result": nas_idx})
            return results

        self.run_background(task, self.show_packet_results, self.background_error)

    def cancel_packet_search(self):
        self.packet_cancel_event.set()
        self.packet_status.setText("Cancelling search...")

    def show_packet_results(self, results):
        self.packet_results = list(results)
        self.packet_table.setSortingEnabled(False)
        self.packet_table.setRowCount(0)
        for index, result in enumerate(self.packet_results):
            row = self.packet_table.rowCount()
            self.packet_table.insertRow(row)
            select_item = QTableWidgetItem()
            select_item.setFlags((select_item.flags() | Qt.ItemIsUserCheckable) & ~Qt.ItemIsEditable)
            select_item.setCheckState(Qt.Unchecked)
            select_item.setData(Qt.UserRole, index)
            self.packet_table.setItem(row, 0, select_item)
            values = [
                result.packet_id,
                result.packet_name,
                self.source_display_name(result.nas_source),
                result.profile or self.source_display_name(result.nas_source),
                result.found_location,
                format_bytes(result.size),
                result.modified_time or "",
                result.status,
                result.error,
            ]
            for column, value in enumerate(values):
                item = readonly_item(value)
                table_column = column + 1
                if table_column == 8:
                    item.setBackground(QColor(STATUS_COLORS.get(result.status, "#ffffff")))
                self.packet_table.setItem(row, table_column, item)
        self.packet_table.setSortingEnabled(True)
        self.apply_packet_result_filter()
        found = sum(1 for result in self.packet_results if result.status == "Found")
        self.packet_status.setText(f"Search complete. Found rows: {found}.")
        self.packet_progress.setValue(self.packet_progress.maximum())
        self.log_action("INFO", "Packet Search", f"Packet search complete; found rows: {found}")

    def create_packet_folder(self):
        nas_name = self.packet_target_nas.currentText()
        folder = normalize_remote_path(self.packet_target_folder.text())

        def task():
            with NasClient(self.nas_config(nas_name), self.chunk_size_mb.value()) as client:
                client.mkdir_p(folder)
            return folder

        self.run_background(
            task,
            lambda created: QMessageBox.information(self, "Folder Created", f"Created or verified:\n{created}"),
            self.background_error,
        )

    def copy_selected_packets(self):
        results = self.selected_packet_results()
        if not results:
            QMessageBox.warning(self, "Copy Packets", "Select one or more found packets.")
            return
        target_nas = self.packet_target_nas.currentText()
        target_folder = normalize_remote_path(self.packet_target_folder.text())
        self.packet_status.setText("Copying selected packets...")

        def task():
            copied = []
            for result in results:
                destination = copy_remote_to_remote(
                    self.config_for_source(result.nas_source),
                    self.nas_config(target_nas),
                    result.found_location,
                    target_folder,
                    self.chunk_size_mb.value(),
                )
                copied.append(destination)
            return copied

        self.run_background(
            task,
            lambda copied: self.packet_status.setText(f"Copied {len(copied)} packet file(s)."),
            self.background_error,
        )

    def download_selected_packets(self):
        results = self.selected_packet_results()
        if not results:
            QMessageBox.warning(self, "Download Packets", "Select one or more found packets.")
            return
        folder = QFileDialog.getExistingDirectory(self, "Choose Download Folder")
        if not folder:
            return
        self.packet_status.setText("Downloading selected packets...")

        def task():
            downloaded = []
            clients = {}
            try:
                for result in results:
                    client = clients.get(result.nas_source)
                    if client is None:
                        client = NasClient(self.config_for_source(result.nas_source), self.chunk_size_mb.value())
                        client.connect()
                        clients[result.nas_source] = client
                    downloaded.append(client.download_file(result.found_location, folder))
                return downloaded
            finally:
                for client in clients.values():
                    client.close()

        self.run_background(
            task,
            lambda downloaded: self.packet_status.setText(f"Downloaded {len(downloaded)} packet file(s)."),
            self.background_error,
        )

    def download_all_packets(self):
        results = [r for r in self.packet_results if r.status == "Found"]
        if not results:
            QMessageBox.warning(self, "Download Packets", "No packets were found to download.")
            return
        folder = QFileDialog.getExistingDirectory(self, "Choose Download Folder")
        if not folder:
            return
        self.packet_status.setText(f"Downloading {len(results)} packets...")

        def task():
            downloaded = []
            clients = {}
            try:
                for result in results:
                    client = clients.get(result.nas_source)
                    if client is None:
                        client = NasClient(self.config_for_source(result.nas_source), self.chunk_size_mb.value())
                        client.connect()
                        clients[result.nas_source] = client
                    downloaded.append(client.download_file(result.found_location, folder))
                return downloaded
            finally:
                for client in clients.values():
                    client.close()

        self.run_background(
            task,
            lambda downloaded: self.packet_status.setText(f"Downloaded {len(downloaded)} packet file(s)."),
            self.background_error,
        )


    def upload_local_packets(self):
        paths, _filter = QFileDialog.getOpenFileNames(self, "Choose Packet Files")
        if not paths:
            return
        nas_name = self.packet_target_nas.currentText()
        target_folder = normalize_remote_path(self.packet_target_folder.text())
        self.packet_status.setText("Uploading selected files...")

        def task():
            uploaded = []
            with NasClient(self.nas_config(nas_name), self.chunk_size_mb.value()) as client:
                for path in paths:
                    uploaded.append(client.upload_file(path, target_folder))
            return uploaded

        self.run_background(
            task,
            lambda uploaded: self.packet_status.setText(f"Uploaded {len(uploaded)} file(s)."),
            self.background_error,
        )

    def export_packet_results(self):
        if not self.packet_results:
            QMessageBox.warning(self, "Export CSV", "There are no packet results to export.")
            return
        path, _filter = QFileDialog.getSaveFileName(self, "Export Packet Results", "packet_results.csv", "CSV (*.csv)")
        if not path:
            return
        Path(path).write_text(packet_results_to_csv(self.packet_results), encoding="utf-8")
        QMessageBox.information(self, "Export CSV", f"Exported packet results to:\n{path}")

    def fetch_matrix_tickets(self):
        user_name = self.matrix_user_full_name.text().strip()
        direct_ticket_numbers = parse_packet_input(self.matrix_ticket_numbers.text())
        assigned_endpoint = self.matrix_endpoint_assigned_tickets.text()
        if not direct_ticket_numbers and "{user_name}" in assigned_endpoint and not user_name:
            QMessageBox.warning(self, "Matrix API", "Enter your Matrix assignee/login in Settings.")
            return
        user_name = user_name or "me"
        self.save_settings_silent()
        if direct_ticket_numbers:
            self.matrix_status.setText(f"Fetching specific ticket(s): {', '.join(direct_ticket_numbers)}")
            self.log_action("INFO", "Matrix API", f"Fetching specific tickets: {', '.join(direct_ticket_numbers)}")
        else:
            self.matrix_status.setText("Fetching assigned tickets...")
            self.log_action("INFO", "Matrix API", f"Fetching tickets for {user_name}")

        def task():
            def collect(client):
                if direct_ticket_numbers:
                    tickets = [{"id": ticket_number, "number": ticket_number} for ticket_number in direct_ticket_numbers]
                else:
                    self.events.put({"type": "ui_call", "callback": self.set_matrix_status, "result": "Fetching assigned tickets list from Redmine..."})
                    tickets = client.get_assigned_tickets(user_name)

                self.events.put({"type": "ui_call", "callback": self.matrix_progress.setMaximum, "result": len(tickets)})
                self.events.put({"type": "ui_call", "callback": self.matrix_progress.setValue, "result": 0})

                comments_by_ticket = {}
                comment_count = 0
                for index, ticket in enumerate(tickets):
                    ticket_id = str(ticket.get("id") or ticket.get("ticket_id") or ticket.get("key") or ticket.get("number") or "")
                    if ticket_id:
                        self.events.put({"type": "ui_call", "callback": self.set_matrix_status, "result": f"Fetching comments for ticket {ticket_id} ({index + 1}/{len(tickets)})..."})
                        comments_by_ticket[ticket_id] = client.get_ticket_comments(ticket_id)
                        comment_count += len(comments_by_ticket[ticket_id])
                    self.events.put({"type": "ui_call", "callback": self.matrix_progress.setValue, "result": index + 1})
                return {
                    "matches": build_matrix_matches(tickets, comments_by_ticket, self.matrix_destination_root.text()),
                    "ticket_count": len(tickets),
                    "comment_count": comment_count,
                    "direct_ticket_numbers": direct_ticket_numbers,
                }

            try:
                return collect(self.matrix_client())
            except MatrixCertificateError:
                self.events.put(
                    {
                        "type": "ui_call",
                        "callback": self.enable_internal_matrix_certificate_mode,
                        "result": None,
                    }
                )
                return collect(self.build_matrix_client(False))

        self.run_background(task, self.show_matrix_matches, self.background_error)

    def show_matrix_matches(self, result):
        if isinstance(result, dict):
            matches = result.get("matches", [])
            ticket_count = result.get("ticket_count", 0)
            comment_count = result.get("comment_count", 0)
            direct_ticket_numbers = result.get("direct_ticket_numbers") or []
        else:
            matches = result
            ticket_count = 0
            comment_count = 0
            direct_ticket_numbers = []
        self.matrix_matches = list(matches)
        self.render_matrix_matches()
        if direct_ticket_numbers:
            source = f" from ticket(s) {', '.join(direct_ticket_numbers)}"
        else:
            source = ""
        self.matrix_status.setText(
            f"Scanned {ticket_count} ticket(s), {comment_count} comment(s){source}; "
            f"matched {len(self.matrix_matches)} backend-restoration comment(s)."
        )
        self.log_action("INFO", "Matrix API", f"Matched Matrix tickets: {len(self.matrix_matches)}")

    def render_matrix_matches(self):
        self.matrix_table.setSortingEnabled(False)
        self.matrix_table.setRowCount(0)
        for index, match in enumerate(self.matrix_matches):
            row = self.matrix_table.rowCount()
            self.matrix_table.insertRow(row)
            select_item = QTableWidgetItem()
            select_item.setFlags((select_item.flags() | Qt.ItemIsUserCheckable) & ~Qt.ItemIsEditable)
            select_item.setCheckState(Qt.Unchecked)
            select_item.setData(Qt.UserRole, index)
            self.matrix_table.setItem(row, 0, select_item)
            values = [
                match.ticket_number,
                ", ".join(match.packet_ids),
                match.comment_author,
                match.destination_folder,
                match.planned_due_date,
                str(len(match.found_packets)),
                self.matrix_match_sources(match),
                match.status,
                match.error,
                "✓" if getattr(match, "packet_copied", False) else "",
                "✓" if getattr(match, "ticket_commented", False) else "",
            ]
            for column, value in enumerate(values):
                item = readonly_item(value)
                table_column = column + 1
                if table_column == 1:
                    item.setData(Qt.UserRole, index)
                if table_column == 8:
                    item.setBackground(QColor(STATUS_COLORS.get(match.status, "#ffffff")))
                item.setToolTip(str(values[table_column - 1]))
                # Center-align most columns; left-align destination folder and error
                if table_column not in (4, 9):
                    item.setTextAlignment(Qt.AlignCenter)
                self.matrix_table.setItem(row, table_column, item)
        self.matrix_table.resizeRowsToContents()
        self.matrix_table.setSortingEnabled(True)

    def toggle_matrix_select_all(self):
        all_checked = True
        for row in range(self.matrix_table.rowCount()):
            item = self.matrix_table.item(row, 0)
            if item and item.checkState() != Qt.Checked:
                all_checked = False
                break
        
        new_state = Qt.Unchecked if all_checked else Qt.Checked
        for row in range(self.matrix_table.rowCount()):
            item = self.matrix_table.item(row, 0)
            if item:
                item.setCheckState(new_state)

    def select_ready_to_execute_matrix_matches(self):
        for row in range(self.matrix_table.rowCount()):
            checkbox_item = self.matrix_table.item(row, 0)
            status_item = self.matrix_table.item(row, 8)  # Index 8 is the Status column
            if checkbox_item and status_item:
                if status_item.text() == "Ready to Execute":
                    checkbox_item.setCheckState(Qt.Checked)
                else:
                    checkbox_item.setCheckState(Qt.Unchecked)

    def show_matrix_context_menu(self, pos):
        row = self.matrix_table.rowAt(pos.y())
        if row < 0:
            return
        
        menu = QMenu(self)
        
        copy_ticket_action = menu.addAction("Copy Ticket Number")
        copy_packet_ids_action = menu.addAction("Copy Packet IDs")
        
        action = menu.exec(self.matrix_table.mapToGlobal(pos))
        
        if action == copy_ticket_action:
            ticket_item = self.matrix_table.item(row, 1)
            if ticket_item:
                QApplication.clipboard().setText(ticket_item.text())
        elif action == copy_packet_ids_action:
            packet_ids_item = self.matrix_table.item(row, 2)
            if packet_ids_item:
                QApplication.clipboard().setText(packet_ids_item.text())

    def matrix_match_sources(self, match):
        sources = []
        seen = set()
        for packet in getattr(match, "found_packets", []) or []:
            label = packet.profile or self.source_display_name(packet.nas_source)
            key = label.casefold()
            if key in seen:
                continue
            seen.add(key)
            sources.append(label)
        return ", ".join(sources)

    def preview_matrix_actions(self):
        if not self.matrix_matches:
            QMessageBox.warning(self, "Matrix Preview", "Fetch assigned tickets first.")
            return
        if self.matrix_worker_thread and self.matrix_worker_thread.is_alive():
            QMessageBox.warning(self, "Matrix Preview", "A Matrix packet search is already running.")
            return
        scope = self.matrix_scope.currentText()
        try:
            search_configs = self.search_configs_for_scope(scope, self.selected_matrix_province_profile_id())
        except Exception as error:
            QMessageBox.critical(self, "Matrix Preview", str(error))
            return
        selected_matches = self.selected_matrix_matches()
        target_matches = selected_matches or list(self.matrix_matches)
        if selected_matches:
            self.matrix_status.setText(f"Syncing ticket and packet data for {len(target_matches)} checked row(s)...")
        else:
            self.matrix_status.setText(f"Syncing ticket and packet data for {len(target_matches)} row(s)...")
        self.matrix_cancel_event.clear()
        self.matrix_progress.setMaximum(len(search_configs))
        self.matrix_progress.setValue(0)

        def task():
            # --- Step 1: Re-verify "Already Executed" entries against NAS1 ---
            already_executed = [m for m in target_matches if m.status == "Already Executed"]
            if already_executed:
                self.events.put({"type": "ui_call", "callback": self.set_matrix_status,
                                  "result": f"Verifying {len(already_executed)} 'Already Executed' entries on NAS1..."})
                try:
                    nas1_config = self.nas_config("NAS1")
                    with NasClient(nas1_config, self.chunk_size_mb.value()) as nas1:
                        for match in already_executed:
                            verified = False
                            filenames = nas1.list_dir_filenames(match.destination_folder)
                            if filenames:
                                for packet_id in match.packet_ids:
                                    if any(packet_id.casefold() in f.casefold() for f in filenames):
                                        verified = True
                                        match.packet_copied = True
                                        match.ticket_commented = True
                                        break
                            if not verified:
                                match.status = "Pending"
                                match.packet_copied = False
                                match.ticket_commented = False
                                match.error = "Destination folder or packet not found on NAS — re-queued for execution."
                except Exception as verify_error:
                    # Cannot connect to NAS1 to verify — leave statuses as-is
                    pass

            # --- Step 2: Build packet ID list from non-skipped matches ---
            packet_ids = []
            seen = set()
            for match in target_matches:
                match.found_packets = []
                if match.status in ("Manual review", "Already Executed"):
                    continue
                match.status = "Searching NAS"
                match.error = ""
                for packet_id in match.packet_ids:
                    key = packet_id.casefold()
                    if key not in seen:
                        seen.add(key)
                        packet_ids.append(packet_id)
            machine_folder_cache = {packet_id: machine_folder_for_packet(packet_id) for packet_id in packet_ids}

            # --- Step 3: Search each NAS, stop early for found packets ---
            found_by_key = {}
            remaining = list(packet_ids)
            for nas_index, (source_name, config, default_root) in enumerate(search_configs, start=1):
                if self.matrix_cancel_event.is_set():
                    return {"cancelled": True, "matches": self.matrix_matches}
                if not remaining:
                    break

                self.events.put(
                    {
                        "type": "ui_call",
                        "callback": self.set_matrix_status,
                        "result": (
                            f"Searching {self.source_display_name(source_name)} for {len(remaining)} remaining packet ID(s) "
                            f"({nas_index}/{len(search_configs)})..."
                        ),
                    }
                )
                self.events.put({"type": "ui_call", "callback": lambda v: self.matrix_progress.setValue(v), "result": nas_index})

                with NasClient(config, self.chunk_size_mb.value()) as client:
                    machine_folder_by_packet = {
                        packet_id: machine_folder_cache.get(packet_id, "")
                        for packet_id in remaining
                        if machine_folder_cache.get(packet_id)
                    }
                    results = []
                    if machine_folder_by_packet:
                        results.extend(client.search_packets_by_machine_folders(
                            list(machine_folder_by_packet.keys()),
                            machine_folder_by_packet,
                            default_root,
                            max_results_per_packet=1,
                            cancel_event=self.matrix_cancel_event,
                        ))

                    unmapped = [pid for pid in remaining if pid not in machine_folder_by_packet]
                    if unmapped:
                        results.extend(client.search_packets(
                            unmapped,
                            default_root,
                            max_results_per_packet=1,
                            cancel_event=self.matrix_cancel_event,
                            stop_when_all_found=True,
                        ))

                for result in results:
                    if result.status != "Found":
                        continue
                    found_by_key.setdefault(result.packet_id.casefold(), []).append(result)

                remaining = [packet_id for packet_id in remaining if packet_id.casefold() not in found_by_key]

            if self.matrix_cancel_event.is_set():
                return {"cancelled": True, "matches": self.matrix_matches}

            for match in target_matches:
                if match.status in ("Manual review", "Already Executed", "Completed"):
                    continue
                for packet_id in match.packet_ids:
                    match.found_packets.extend(found_by_key.get(packet_id.casefold(), []))
                
                # Check for "already finished" items
                if getattr(match, "packet_copied", False) and getattr(match, "ticket_commented", False):
                    match.status = "Completed"
                    match.error = ""
                elif getattr(match, "packet_copied", False):
                    # They have the packet copied but missing comment
                    match.status = "Ready to Execute"
                    match.error = ""
                elif match.found_packets:
                    # Not copied yet, but found
                    match.status = "Ready to Execute"
                    match.error = ""
                else:
                    # Completely missing and not already copied
                    match.status = "Packet Missing"
                    match.error = "No packet file was found in the selected NAS scope."

            return {
                "cancelled": False,
                "matches": self.matrix_matches,
                "searched_rows": len(target_matches),
                "searched_packet_ids": len(packet_ids),
                "found_packet_ids": len(found_by_key),
            }

        def on_success(result):
            self.render_matrix_matches()
            if result.get("cancelled"):
                self.matrix_status.setText("Sync cancelled. Partial results were kept.")
            else:
                self.matrix_status.setText(
                    "Sync complete. "
                    f"Searched {result.get('searched_rows', 0)} row(s), "
                    f"{result.get('searched_packet_ids', 0)} packet ID(s); "
                    f"found {result.get('found_packet_ids', 0)} packet ID(s)."
                )
            self.matrix_worker_thread = None

        def on_error(error):
            self.matrix_worker_thread = None
            if str(error) == "Packet search cancelled.":
                self.render_matrix_matches()
                self.matrix_status.setText("Sync cancelled. Partial results were kept.")
                return
            self.background_error(error)

        def wrapper():
            try:
                result = task()
                self.events.put({"type": "ui_call", "callback": on_success, "result": result})
            except Exception as error:
                self.events.put({"type": "ui_error", "callback": on_error, "error": error})

        self.matrix_worker_thread = threading.Thread(target=wrapper, daemon=True)
        self.matrix_worker_thread.start()

    def selected_matrix_matches(self):
        rows = range(self.matrix_table.rowCount())
        matches = []
        for row in rows:
            item = self.matrix_table.item(row, 0)
            if not item or item.checkState() != Qt.Checked:
                continue
            match_index = item.data(Qt.UserRole)
            if isinstance(match_index, int) and 0 <= match_index < len(self.matrix_matches):
                matches.append(self.matrix_matches[match_index])
        return matches

    def execute_all_matrix_actions(self, _checked=False):
        self.execute_matrix_actions(execute_all=True)

    def execute_matrix_actions(self, _checked=False, execute_all=False):
        matches = list(self.matrix_matches) if execute_all else self.selected_matrix_matches()
        if not matches:
            QMessageBox.warning(
                self,
                "Matrix Execute",
                "Check one or more ticket rows first." if not execute_all else "There are no ticket rows to execute.",
            )
            return
        action_label = "all Matrix updates" if execute_all else "selected Matrix updates"
        if (
            QMessageBox.question(
                self,
                "Confirm Matrix Updates",
                f"This will copy packets to NAS1 and update Matrix tickets for {action_label}. Continue?",
            )
            != QMessageBox.Yes
        ):
            return
        self.matrix_status.setText(f"Executing {action_label}...")
        total_tasks = len(matches)
        self.matrix_progress.setMaximum(total_tasks)
        self.matrix_progress.setValue(0)

        def task():
            client = self.matrix_client()
            nas1_config = self.nas_config("NAS1")
            completed = 0
            for match in matches:
                if match.status in ("Manual review", "Packet not found", "Packet Missing", "Already Executed") or not match.found_packets:
                    match.status = "Manual review"
                    match.error = match.error or "Run Sync Ticket and Packet and resolve missing packets before execution."
                    continue

                # --- Copy packets to NAS1 destination ---
                copied = []        # list of (dest_path, filename)
                copy_errors = []
                for packet in match.found_packets:
                    try:
                        import posixpath
                        from .nas_client import remote_join
                        filename = posixpath.basename(packet.found_location)
                        expected_dest = remote_join(match.destination_folder, filename)
                        if packet.nas_source == "NAS1" and packet.found_location == expected_dest:
                            copied.append((expected_dest, filename))
                        else:
                            dest_path = copy_remote_to_remote(
                                self.config_for_source(packet.nas_source),
                                nas1_config,
                                packet.found_location,
                                match.destination_folder,
                                self.chunk_size_mb.value(),
                            )
                            copied.append((dest_path, filename))
                    except Exception as error:
                        copy_errors.append(f"{posixpath.basename(packet.found_location)}: {error}")

                if not copied:
                    match.status = "Packet Not Copied"
                    match.error = "No packet was copied to NAS — ticket was not updated."
                    continue

                if copy_errors and not self.matrix_allow_partial.isChecked():
                    match.status = "Copy Failed"
                    match.error = "Some packets failed to copy and Allow Partial is off — ticket was not updated. " + "; ".join(copy_errors)
                    continue

                match.packet_copied = True
                match.status = "Packet Copied to NAS ✓"

                # --- Verify packet actually exists on NAS1 before commenting ---
                try:
                    with NasClient(nas1_config, self.chunk_size_mb.value()) as nas1_verify:
                        verified_names = nas1_verify.list_dir_filenames(match.destination_folder)
                        any_verified = any(
                            dest_name.casefold() in (n.casefold() for n in verified_names)
                            for _, dest_name in copied
                        )
                    if not any_verified:
                        match.status = "Copy Unverified"
                        match.error = "Packet copy completed but file not found on NAS1 during verification — ticket was not updated."
                        continue
                except Exception as verify_err:
                    match.status = "Copy Unverified"
                    match.error = f"Could not verify packet on NAS1: {verify_err} — ticket was not updated."
                    continue

                # --- Post comment with list of copied packet filenames ---
                packet_lines = "\n".join(f"• {fname}" for _, fname in copied)
                comment = (
                    f"Packet(s) uploaded in this directory\n"
                    f"{match.destination_folder}\n\n"
                    f"{packet_lines}"
                )
                try:
                    client.update_assignee(match.ticket_id, match.comment_author_id or match.comment_author)
                    client.update_due_date(match.ticket_id, match.planned_due_date)
                    client.post_comment(match.ticket_id, comment)
                    match.ticket_commented = True
                    match.status = "Executed ✓"
                    match.error = "; ".join(copy_errors) if copy_errors else ""
                except Exception as comment_err:
                    match.status = "Packet Copied — Comment Failed"
                    match.error = f"Packet was copied successfully, but ticket update failed: {comment_err}"

                completed += 1
                self.events.put({"type": "ui_call", "callback": lambda r: self.matrix_progress.setValue(r), "result": completed})
            return completed

        def on_complete(completed):
            self.render_matrix_matches()
            self.matrix_status.setText(f"Completed {completed} Matrix ticket update(s).")
            self.matrix_progress.setValue(self.matrix_progress.maximum())
            QMessageBox.information(self, "Execution Finished", f"Task has been finished. Completed {completed} Matrix ticket update(s).")

        self.run_background(
            task,
            on_complete,
            self.background_error,
        )

    def poll_events(self):
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break
            self.handle_event(event)

    def handle_event(self, event):
        event_type = event.get("type")
        if event_type == "ui_call":
            callback = event.get("callback")
            if callback:
                callback(event.get("result"))
        elif event_type == "ui_error":
            callback = event.get("callback") or self.background_error
            callback(event.get("error"))
        elif event_type == "job":
            self.current_job_key = event["job_key"]
            self.load_recent_rows()
        elif event_type == "status":
            status = event.get("status", "Ready")
            if status.startswith("Connecting to source"):
                set_badge(self.source_status, "Testing")
            elif status.startswith("Connecting to destination"):
                set_badge(self.source_status, "Connected")
                set_badge(self.destination_status, "Testing")
            elif status == "Completed":
                set_badge(self.source_status, "Connected")
                set_badge(self.destination_status, "Connected")
                set_badge(self.status, "Completed")
            elif status == "Cancelled":
                set_badge(self.status, "Paused")
            else:
                set_badge(self.status, "Running" if status not in ("Ready", "Paused") else status)
            if event.get("current_file"):
                self.current_file.setText(event["current_file"])
        elif event_type == "counts":
            self.update_counts(event["counts"])
        elif event_type == "row":
            self.update_table_row(event["row"])
        elif event_type == "file_progress":
            size = event.get("file_size") or 0
            copied = event.get("copied_bytes") or 0
            self.file_progress.setValue(int((copied / size) * 100) if size else 0)
        elif event_type == "error":
            set_badge(self.status, "Failed")
            self.log_action("ERROR", "Transfer", event.get("message", "Error"))
        elif event_type == "fatal":
            set_badge(self.status, "Failed")
            set_badge(self.source_status, "Failed")
            set_badge(self.destination_status, "Failed")
            QMessageBox.critical(self, "Transfer Error", event.get("message", "Transfer failed."))
        elif event_type == "cancelled":
            QMessageBox.information(self, "Cancelled", "Transfer cancelled. State was saved in SQLite.")
        elif event_type == "complete":
            counts = event.get("counts", {})
            QMessageBox.information(
                self,
                "Transfer Complete",
                "Transfer finished.\n\n"
                f"Total: {counts.get('total_files', 0)}\n"
                f"Verified: {counts.get('verified', 0)}\n"
                f"Copied: {counts.get('copied', 0)}\n"
                f"Skipped: {counts.get('skipped', 0)}\n"
                f"Failed: {counts.get('failed', 0)}",
            )

    def update_counts(self, counts):
        total_files = counts.get("total_files", 0)
        copied = counts.get("copied", 0)
        skipped = counts.get("skipped", 0)
        verified = counts.get("verified", 0)
        failed = counts.get("failed", 0)
        partial = counts.get("partial", 0)
        pending = counts.get("pending", 0) + counts.get("copying", 0) + partial
        completed = copied + skipped + verified
        total_size = counts.get("total_size", 0)
        data_done = counts.get("data_done", 0)

        self.metric_labels["Total files"].setText(str(total_files))
        self.metric_labels["Completed"].setText(str(completed))
        self.metric_labels["Skipped"].setText(str(skipped))
        self.metric_labels["Verified"].setText(str(verified))
        self.metric_labels["Pending"].setText(str(pending))
        self.metric_labels["Failed"].setText(str(failed))
        self.metric_labels["Total size"].setText(format_bytes(total_size))
        self.metric_labels["Data done"].setText(format_bytes(data_done))
        self.overall_progress.setValue(int((data_done / total_size) * 100) if total_size else 0)

        now = time.monotonic()
        elapsed = max(now - self.last_speed_time, 0.001)
        delta = max(data_done - self.last_data_done, 0)
        if elapsed >= 1:
            self.current_speed = delta / elapsed
            self.last_data_done = data_done
            self.last_speed_time = now

        average_elapsed = max(now - self.average_start_time, 0.001)
        average_speed = data_done / average_elapsed if data_done else 0
        self.metric_labels["Live speed"].setText(f"{format_bytes(self.current_speed)}/s" if self.current_speed else "-")
        self.metric_labels["Average speed"].setText(f"{format_bytes(average_speed)}/s" if average_speed else "-")
        remaining = max(total_size - data_done, 0)
        eta = remaining / self.current_speed if self.current_speed else None
        self.metric_labels["ETA"].setText(format_eta(eta))

    def update_table_row(self, row):
        key = row["relative_file_path"]
        sorting = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)

        if key in self.table_rows:
            table_row = self.table_rows[key]
        else:
            table_row = self.table.rowCount()
            self.table.insertRow(table_row)
            self.table_rows[key] = table_row

        values = [
            row["relative_file_path"],
            row["source_path"],
            row["destination_path"],
            format_bytes(row["file_size"]),
            row["status"],
            row["last_error"] or "",
            row["last_updated"],
        ]

        for column, value in enumerate(values):
            item = readonly_item(value)
            if column == 0:
                item.setData(Qt.UserRole, key)
            if column == 4:
                item.setBackground(QColor(STATUS_COLORS.get(str(value), "#ffffff")))
            self.table.setItem(table_row, column, item)
        self.table.setSortingEnabled(sorting)
        self.apply_file_filter()

    def load_recent_rows(self):
        if not self.current_job_key:
            return
        for row in reversed(self.db.recent_rows(self.current_job_key)):
            self.update_table_row(row)

    def apply_file_filter(self):
        text = self.file_filter.text().strip().casefold()
        for row in range(self.table.rowCount()):
            if not text:
                self.table.setRowHidden(row, False)
                continue
            values = []
            for column in range(self.table.columnCount()):
                item = self.table.item(row, column)
                values.append(item.text().casefold() if item else "")
            self.table.setRowHidden(row, text not in " ".join(values))

    def show_file_context_menu(self, position):
        row = self.table.rowAt(position.y())
        if row < 0:
            return
        menu = QMenu(self)
        retry_action = menu.addAction("Retry file")
        open_source_action = menu.addAction("Open source location")
        open_destination_action = menu.addAction("Open destination location")
        copy_path_action = menu.addAction("Copy path")
        view_error_action = menu.addAction("View error")
        action = menu.exec(self.table.viewport().mapToGlobal(position))
        relative_item = self.table.item(row, 0)
        source_item = self.table.item(row, 1)
        destination_item = self.table.item(row, 2)
        error_item = self.table.item(row, 5)
        if not relative_item:
            return
        relative_path = relative_item.data(Qt.UserRole) or relative_item.text()

        if action == retry_action and self.current_job_key:
            self.db.set_status(
                self.current_job_key,
                relative_path,
                STATUS_PENDING,
                copied_bytes=0,
                verified=False,
                error="Marked for retry by user.",
            )
            self.emit_row_from_db(relative_path)
            self.retry_failed()
        elif action == open_source_action and source_item:
            self.copy_remote_folder(source_item.text())
        elif action == open_destination_action and destination_item:
            self.copy_remote_folder(destination_item.text())
        elif action == copy_path_action and destination_item:
            QApplication.clipboard().setText(destination_item.text())
        elif action == view_error_action and error_item:
            QMessageBox.information(self, "File Error", error_item.text() or "No error recorded.")

    def emit_row_from_db(self, relative_path):
        row = self.db.get_row(self.current_job_key, relative_path)
        if row:
            self.update_table_row(row)

    def copy_remote_folder(self, remote_path):
        folder = str(remote_path).rsplit("/", 1)[0] or "/"
        QApplication.clipboard().setText(folder)
        QMessageBox.information(self, "Remote Folder", f"Remote folder copied to clipboard:\n{folder}")

    def log_action(self, level, category, message):
        safe_message = str(message)
        token = self.matrix_api_token.text()
        if token:
            safe_message = safe_message.replace(token, safe_token_preview(token))
        logger_method = getattr(self.app_logger, level.lower(), self.app_logger.info)
        logger_method("[%s] %s", category, safe_message)
        self.refresh_logs()

    def refresh_logs(self):
        if not hasattr(self, "log_view"):
            return
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        files = sorted(LOG_DIR.glob("*.log"), key=lambda path: path.stat().st_mtime, reverse=True)[:10]
        lines = []
        for path in reversed(files):
            try:
                lines.extend(path.read_text(encoding="utf-8", errors="replace").splitlines())
            except OSError:
                pass
        filtered = [line for line in lines if self.log_line_visible(line)]
        self.log_view.setPlainText("\n".join(filtered[-3000:]))
        self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())

    def copy_selected_logs(self):
        text = self.log_view.textCursor().selectedText().replace("\u2029", "\n")
        if not text:
            QMessageBox.information(self, "Copy Logs", "Select one or more log lines first.")
            return
        QApplication.clipboard().setText(text)

    def clear_visible_logs(self):
        self.log_view.clear()

    def log_line_visible(self, line):
        lowered = line.lower()
        severity_selected = (
            ("[info]" in lowered and self.log_filter_info.isChecked())
            or ("[warning]" in lowered and self.log_filter_warning.isChecked())
            or ("[error]" in lowered and self.log_filter_error.isChecked())
            or ("[critical]" in lowered and self.log_filter_error.isChecked())
        )
        if not severity_selected:
            return False
        category_selected = (
            ("[transfer]" in lowered and self.log_filter_transfer.isChecked())
            or ("[matrix" in lowered and self.log_filter_matrix.isChecked())
            or ("[packet" in lowered and self.log_filter_packet.isChecked())
            or (
                "[transfer]" not in lowered
                and "[matrix" not in lowered
                and "[packet" not in lowered
            )
        )
        return category_selected

    def export_logs(self):
        path, _filter = QFileDialog.getSaveFileName(self, "Export Logs", "nas_transfer_logs.txt", "Text (*.txt)")
        if not path:
            return
        Path(path).write_text(self.log_view.toPlainText(), encoding="utf-8")
        QMessageBox.information(self, "Export Logs", f"Logs exported to:\n{path}")


def run_app():
    app = QApplication.instance() or QApplication([])
    app.setQuitOnLastWindowClosed(False)
    app_icon = QIcon(str(resource_path("assets/nas_transfer_icon_new.png")))
    if not app_icon.isNull():
        app.setWindowIcon(app_icon)
    window = MainWindow()
    window.show()
    app.exec()
