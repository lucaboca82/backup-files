# main.py

import os
import shutil
import threading
import time
import hashlib
import configparser
import logging
from logging.handlers import RotatingFileHandler
import queue
import fnmatch
import zipfile
import smtplib
import base64
import webbrowser
from email.message import EmailMessage
from cryptography.fernet import Fernet
from apscheduler.schedulers.background import BackgroundScheduler
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog
from tkinter import ttk

CONFIG_PATH = 'config.ini'
LOG_PATH = 'backup.log'
DOC_URL = 'https://example.com/backup-tool-docs.pdf'


def compute_sha256(path, block_size=65536):
    """Compute SHA-256 hash for a file."""
    sha = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha.update(block)
    return sha.hexdigest()


def derive_key(password: str, salt: bytes = b'some_static_salt'):
    """Derive a Fernet key from a password."""
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
    return base64.urlsafe_b64encode(dk)


class BackupApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Backup & Sync Tool")
        self.geometry("780x650")
        self.resizable(False, False)

        # UI variables
        self.src_dir = tk.StringVar()
        self.dst_dir = tk.StringVar()
        self.delete_old = tk.BooleanVar(value=False)
        self.use_compression = tk.BooleanVar(value=False)
        self.use_encryption = tk.BooleanVar(value=False)
        self.encryption_pwd = tk.StringVar()
        self.retention_count = tk.IntVar(value=5)
        self.schedule_enabled = tk.BooleanVar(value=False)
        self.schedule_interval = tk.IntVar(value=24)  # hours
        self.exclude_patterns = []

        # Email settings
        self.smtp_server = tk.StringVar()
        self.smtp_port = tk.IntVar(value=587)
        self.smtp_user = tk.StringVar()
        self.smtp_password = tk.StringVar()
        self.notify_email = tk.StringVar()

        # internal
        self._task_thread = None
        self._log_queue = queue.Queue()
        self._total_files = 0
        self._processed_files = 0
        self.scheduler = BackgroundScheduler()

        self._load_config()
        self._setup_logging()
        self._build_menu()
        self._build_ui()
        self._start_scheduler_if_enabled()
        self.after(100, self._flush_log_queue)

    def _setup_logging(self):
        """Configure rotating file and console logging."""
        handler = RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=3)
        fmt = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s', '%Y-%m-%d %H:%M:%S')
        handler.setFormatter(fmt)
        console = logging.StreamHandler()
        console.setFormatter(fmt)

        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        logger.addHandler(console)
        logger.info("Application started")

    def _load_config(self):
        """Load settings from INI file."""
        cfg = configparser.ConfigParser()
        if not os.path.exists(CONFIG_PATH):
            return
        cfg.read(CONFIG_PATH)

        if cfg.has_section('paths'):
            self.src_dir.set(cfg.get('paths', 'src', fallback=''))
            self.dst_dir.set(cfg.get('paths', 'dst', fallback=''))
        if cfg.has_section('options'):
            self.delete_old.set(cfg.getboolean('options', 'delete_old', False))
            self.use_compression.set(cfg.getboolean('options', 'compression', False))
            self.use_encryption.set(cfg.getboolean('options', 'encryption', False))
            self.retention_count.set(cfg.getint('options', 'retention', 5))
            self.encryption_pwd.set(cfg.get('options', 'encryption_pwd', fallback=''))
        if cfg.has_section('schedule'):
            self.schedule_enabled.set(cfg.getboolean('schedule', 'enabled', False))
            self.schedule_interval.set(cfg.getint('schedule', 'interval', 24))
        if cfg.has_section('advanced'):
            excl = cfg.get('advanced', 'excludes', fallback='')
            self.exclude_patterns = excl.split(';') if excl else []
        if cfg.has_section('email'):
            self.smtp_server.set(cfg.get('email', 'server', fallback=''))
            self.smtp_port.set(cfg.getint('email', 'port', fallback=587))
            self.smtp_user.set(cfg.get('email', 'user', fallback=''))
            self.smtp_password.set(cfg.get('email', 'password', fallback=''))
            self.notify_email.set(cfg.get('email', 'to', fallback=''))

    def _save_config(self):
        """Persist settings to INI file."""
        cfg = configparser.ConfigParser()
        cfg['paths'] = {'src': self.src_dir.get(), 'dst': self.dst_dir.get()}
        cfg['options'] = {
            'delete_old': str(self.delete_old.get()),
            'compression': str(self.use_compression.get()),
            'encryption': str(self.use_encryption.get()),
            'retention': str(self.retention_count.get()),
            'encryption_pwd': self.encryption_pwd.get()
        }
        cfg['schedule'] = {
            'enabled': str(self.schedule_enabled.get()),
            'interval': str(self.schedule_interval.get())
        }
        cfg['advanced'] = {'excludes': ';'.join(self.exclude_patterns)}
        cfg['email'] = {
            'server': self.smtp_server.get(),
            'port': str(self.smtp_port.get()),
            'user': self.smtp_user.get(),
            'password': self.smtp_password.get(),
            'to': self.notify_email.get()
        }
        with open(CONFIG_PATH, 'w') as f:
            cfg.write(f)
        logging.info("Settings saved to %s", CONFIG_PATH)

    def _build_menu(self):
        """Create menu bar with File, Settings, Help, Documentation."""
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Exit", command=self._on_exit)
        menubar.add_cascade(label="File", menu=file_menu)

        settings_menu = tk.Menu(menubar, tearoff=False)
        settings_menu.add_command(label="Advanced Settings", command=self._open_settings)
        menubar.add_cascade(label="Settings", menu=settings_menu)

        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(label="Documentation", command=lambda: webbrowser.open(DOC_URL))
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def _build_ui(self):
        """Construct main window widgets."""
        pad = {'padx': 8, 'pady': 8}

        # Source
        ttk.Label(self, text="Source Directory:").grid(row=0, column=0, sticky='w', **pad)
        ttk.Entry(self, textvariable=self.src_dir, width=60).grid(row=0, column=1, **pad)
        ttk.Button(self, text="Browse…", command=self._browse_src).grid(row=0, column=2, **pad)

        # Destination
        ttk.Label(self, text="Destination Directory:").grid(row=1, column=0, sticky='w', **pad)
        ttk.Entry(self, textvariable=self.dst_dir, width=60).grid(row=1, column=1, **pad)
        ttk.Button(self, text="Browse…", command=self._browse_dst).grid(row=1, column=2, **pad)

        # Options
        ttk.Checkbutton(self, text="Delete files not present in source",
                        variable=self.delete_old).grid(row=2, column=1, sticky='w', **pad)
        ttk.Checkbutton(self, text="Compress after sync",
                        variable=self.use_compression).grid(row=3, column=1, sticky='w', **pad)
        ttk.Checkbutton(self, text="Encrypt archive",
                        variable=self.use_encryption).grid(row=4, column=1, sticky='w', **pad)

        # Start
        self.start_btn = ttk.Button(self, text="Start Backup", command=self._start_backup)
        self.start_btn.grid(row=5, column=1, **pad)

        # Log area
        self.log_area = scrolledtext.ScrolledText(self, width=95, height=20, state='disabled')
        self.log_area.grid(row=6, column=0, columnspan=3, padx=10, pady=(0, 10))

        # Progress bar
        self.progress = ttk.Progressbar(self, orient='horizontal', length=720, mode='determinate')
        self.progress.grid(row=7, column=0, columnspan=3, padx=20, pady=(0, 10))

    def _browse_src(self):
        path = filedialog.askdirectory()
        if path:
            self.src_dir.set(path)

    def _browse_dst(self):
        path = filedialog.askdirectory()
        if path:
            self.dst_dir.set(path)

    def _start_backup(self):
        """Validate and start backup in a background thread."""
        src, dst = self.src_dir.get(), self.dst_dir.get()
        if not os.path.isdir(src) or not os.path.isdir(dst):
            messagebox.showerror("Invalid Paths", "Select valid source and destination.")
            return
        if self.use_encryption.get() and not self.encryption_pwd.get():
            messagebox.showerror("Missing Password", "Encryption password required.")
            return

        self.start_btn.config(state='disabled')
        self._log(f"Backup request: {src} → {dst} (del_old={self.delete_old.get()})")
        args = (src, dst, self.delete_old.get())
        self._task_thread = threading.Thread(target=self._backup_task, args=args, daemon=True)
        self._task_thread.start()

    # ... rest of methods unchanged ... #

    # (For brevity, retain all previously implemented methods:
    # _backup_task, _sync_directories, _delete_obsolete,
    # _compress_backup, _encrypt_archive, _apply_retention,
    # _send_notification, _advance_progress, _log,
    # _flush_log_queue, _open_settings, _start_scheduler_if_enabled,
    # _reschedule, _scheduled_backup, _show_about, _on_exit)
    # Ensure encryption_pwd entry is in Advanced Settings dialog.

if __name__ == '__main__':
    BackupApp().mainloop()
