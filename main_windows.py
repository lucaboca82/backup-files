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
from tkinter import filedialog, messagebox, scrolledtext
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

        # UI state variables
        self.src_dir = tk.StringVar()
        self.dst_dir = tk.StringVar()
        self.delete_old = tk.BooleanVar(value=False)
        self.use_compression = tk.BooleanVar(value=False)
        self.use_encryption = tk.BooleanVar(value=False)
        self.encryption_pwd = tk.StringVar()
        self.retention_count = tk.IntVar(value=5)
        self.schedule_enabled = tk.BooleanVar(value=False)
        self.schedule_interval = tk.IntVar(value=24)
        self.exclude_patterns = []

        # Email settings
        self.smtp_server = tk.StringVar()
        self.smtp_port = tk.IntVar(value=587)
        self.smtp_user = tk.StringVar()
        self.smtp_password = tk.StringVar()
        self.notify_email = tk.StringVar()

        # internal state
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
        file_handler = RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=3)
        fmt = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s', '%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(fmt)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(fmt)

        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
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
            self.encryption_pwd.set(cfg.get('options', 'encryption_pwd', fallback=''))
            self.retention_count.set(cfg.getint('options', 'retention', 5))
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
        cfg['paths'] = {
            'src': self.src_dir.get(),
            'dst': self.dst_dir.get()
        }
        cfg['options'] = {
            'delete_old': str(self.delete_old.get()),
            'compression': str(self.use_compression.get()),
            'encryption': str(self.use_encryption.get()),
            'encryption_pwd': self.encryption_pwd.get(),
            'retention': str(self.retention_count.get())
        }
        cfg['schedule'] = {
            'enabled': str(self.schedule_enabled.get()),
            'interval': str(self.schedule_interval.get())
        }
        cfg['advanced'] = {
            'excludes': ';'.join(self.exclude_patterns)
        }
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

        ttk.Label(self, text="Source Directory:").grid(row=0, column=0, sticky='w', **pad)
        ttk.Entry(self, textvariable=self.src_dir, width=60).grid(row=0, column=1, **pad)
        ttk.Button(self, text="Browse…", command=self._browse_src).grid(row=0, column=2, **pad)

        ttk.Label(self, text="Destination Directory:").grid(row=1, column=0, sticky='w', **pad)
        ttk.Entry(self, textvariable=self.dst_dir, width=60).grid(row=1, column=1, **pad)
        ttk.Button(self, text="Browse…", command=self._browse_dst).grid(row=1, column=2, **pad)

        ttk.Checkbutton(self, text="Delete files not present in source", variable=self.delete_old
                        ).grid(row=2, column=1, sticky='w', **pad)
        ttk.Checkbutton(self, text="Compress after sync", variable=self.use_compression
                        ).grid(row=3, column=1, sticky='w', **pad)
        ttk.Checkbutton(self, text="Encrypt archive", variable=self.use_encryption
                        ).grid(row=4, column=1, sticky='w', **pad)

        self.start_btn = ttk.Button(self, text="Start Backup", command=self._start_backup)
        self.start_btn.grid(row=5, column=1, **pad)

        self.log_area = scrolledtext.ScrolledText(self, width=95, height=20, state='disabled')
        self.log_area.grid(row=6, column=0, columnspan=3, padx=10, pady=(0, 10))

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
        """Validate and start backup in background."""
        src, dst = self.src_dir.get(), self.dst_dir.get()
        if not os.path.isdir(src) or not os.path.isdir(dst):
            messagebox.showerror("Invalid Paths", "Select valid source and destination.")
            return
        if self.use_encryption.get() and not self.encryption_pwd.get():
            messagebox.showerror("Missing Password", "Encryption password required.")
            return

        self.start_btn.config(state='disabled')
        self._log(f"Starting backup: {src} → {dst}")
        args = (src, dst, self.delete_old.get())
        self._task_thread = threading.Thread(target=self._backup_task, args=args, daemon=True)
        self._task_thread.start()

    def _backup_task(self, src, dst, delete_old):
        """Perform sync, optional deletion, compression, encryption, retention, notification."""
        try:
            all_files = [os.path.join(r, f) for r, _, files in os.walk(src) for f in files]
            self._total_files = len(all_files)
            self._processed_files = 0
            self.progress['maximum'] = self._total_files

            self._sync_directories(src, dst)
            if delete_old:
                self._delete_obsolete(dst, src)

            archive = None
            if self.use_compression.get():
                archive = self._compress_backup(dst)
                if self.use_encryption.get():
                    archive = self._encrypt_archive(archive)

            self._apply_retention(dst if not archive else os.path.dirname(archive))
            self._log("Backup completed successfully.")
            if self.notify_email.get():
                self._send_notification(archive)
        except Exception as e:
            self._log(f"Backup error: {e}")
            logging.exception("Error during backup")
        finally:
            self.start_btn.config(state='normal')

    def _sync_directories(self, src, dst):
        """Copy new or changed files, skip excludes."""
        for root, _, files in os.walk(src):
            rel = os.path.relpath(root, src)
            if any(fnmatch.fnmatch(rel, pat) for pat in self.exclude_patterns):
                continue
            target = os.path.join(dst, rel)
            os.makedirs(target, exist_ok=True)
            for f in files:
                if any(fnmatch.fnmatch(f, pat) for pat in self.exclude_patterns):
                    continue
                src_f = os.path.join(root, f)
                dst_f = os.path.join(target, f)
                try:
                    if os.path.exists(dst_f):
                        s, d = os.stat(src_f), os.stat(dst_f)
                        if s.st_mtime == d.st_mtime and s.st_size == d.st_size:
                            self._advance_progress()
                            continue
                        if compute_sha256(src_f) == compute_sha256(dst_f):
                            self._advance_progress()
                            continue
                    shutil.copy2(src_f, dst_f)
                    os.utime(dst_f, (os.path.getatime(src_f), os.path.getmtime(src_f)))
                    self._log(f"Copied: {src_f} → {dst_f}")
                    logging.info("Copied %s to %s", src_f, dst_f)
                except Exception as ex:
                    self._log(f"Copy failed: {src_f}: {ex}")
                    logging.error("Copy error %s: %s", src_f, ex)
                finally:
                    self._advance_progress()

    def _delete_obsolete(self, dst, src):
        """Remove files and directories not in source."""
        self._log("Removing obsolete items…")
        for root, dirs, files in os.walk(dst, topdown=False):
            rel = os.path.relpath(root, dst)
            src_root = os.path.join(src, rel)
            for f in files:
                dst_f = os.path.join(root, f)
                if not os.path.exists(os.path.join(src_root, f)):
                    os.remove(dst_f)
                    self._log(f"Removed file: {dst_f}")
                    logging.info("Removed %s", dst_f)
            for d in dirs:
                d_path = os.path.join(root, d)
                if not os.listdir(d_path):
                    os.rmdir(d_path)
                    self._log(f"Removed empty dir: {d_path}")
                    logging.info("Removed dir %s", d_path)

    def _compress_backup(self, dst):
        """Create a timestamped ZIP archive of the backup folder."""
        ts = time.strftime("%Y%m%d_%H%M%S")
        archive = os.path.join(dst, f"backup_{ts}.zip")
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
            for root, _, files in os.walk(dst):
                for f in files:
                    if f.endswith('.zip'):
                        continue
                    path = os.path.join(root, f)
                    arcname = os.path.relpath(path, dst)
                    z.write(path, arcname)
        self._log(f"Compressed backup to {archive}")
        logging.info("Archive created %s", archive)
        return archive

    def _encrypt_archive(self, archive):
        """Encrypt the ZIP archive with Fernet."""
        pwd = self.encryption_pwd.get()
        key = derive_key(pwd)
        f = Fernet(key)
        with open(archive, 'rb') as fin:
            data = fin.read()
        token = f.encrypt(data)
        enc_path = archive.replace('.zip', '_enc.bin')
        with open(enc_path, 'wb') as fout:
            fout.write(token)
        os.remove(archive)
        self._log(f"Encrypted archive to {enc_path}")
        logging.info("Encrypted %s", enc_path)
        return enc_path

    def _apply_retention(self, folder):
        """Keep only the last N archives."""
        patterns = ['backup_*.zip', 'backup_*_enc.bin']
        for pat in patterns:
            items = sorted(
                [os.path.join(folder, f) for f in os.listdir(folder) if fnmatch.fnmatch(f, pat)],
                key=os.path.getmtime, reverse=True
            )
            for old in items[self.retention_count.get():]:
                os.remove(old)
                self._log(f"Removed old archive: {old}")
                logging.info("Removed old archive %s", old)

    def _send_notification(self, attachment=None):
        """Email a summary notification with optional attachment."""
        try:
            msg = EmailMessage()
            msg['Subject'] = 'Backup Completed'
            msg['From'] = self.smtp_user.get()
            msg['To'] = self.notify_email.get()
            body = f"Backup finished at {time.strftime('%Y-%m-%d %H:%M:%S')}"
            msg.set_content(body)
            if attachment and os.path.exists(attachment):
                with open(attachment, 'rb') as f:
                    data = f.read()
                msg.add_attachment(
                    data,
                    maintype='application',
                    subtype='octet-stream',
                    filename=os.path.basename(attachment)
                )
            server = smtplib.SMTP(self.smtp_server.get(), self.smtp_port.get(), timeout=30)
            server.starttls()
            server.login(self.smtp_user.get(), self.smtp_password.get())
            server.send_message(msg)
            server.quit()
            self._log(f"Notification emailed to {self.notify_email.get()}")
            logging.info("Email notification sent")
        except Exception as ex:
            self._log(f"Email failed: {ex}")
            logging.error("Notification error: %s", ex)

    def _advance_progress(self):
        """Increment progress bar value."""
        self._processed_files += 1
        self.progress['value'] = self._processed_files

    def _log(self, message):
        """Queue log message for UI and file."""
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self._log_queue.put(f"[{ts}] {message}")
        logging.info(message)

    def _flush_log_queue(self):
        """Transfer queued messages to the text widget."""
        try:
            while True:
                line = self._log_queue.get_nowait()
                self.log_area.config(state='normal')
                self.log_area.insert(tk.END, line + '\n')
                self.log_area.see(tk.END)
                self.log_area.config(state='disabled')
        except queue.Empty:
            pass
        finally:
            self.after(100, self._flush_log_queue)

    def _open_settings(self):
        """Open advanced settings dialog."""
        dlg = tk.Toplevel(self)
        dlg.title("Advanced Settings")
        dlg.geometry("500x500")
        nb = ttk.Notebook(dlg)
        nb.pack(fill='both', expand=True, padx=10, pady=10)

        # Exclusions tab
        frm_ex = ttk.Frame(nb)
        nb.add(frm_ex, text="Exclusions")
        ttk.Label(frm_ex, text="Filename/Path patterns (semicolon-separated):"
                  ).pack(anchor='w', pady=5)
        txt_ex = tk.Text(frm_ex, height=4)
        txt_ex.insert('1.0', ';'.join(self.exclude_patterns))
        txt_ex.pack(fill='x', padx=5)

        # Schedule tab
        frm_sch = ttk.Frame(nb)
        nb.add(frm_sch, text="Schedule")
        ttk.Checkbutton(frm_sch, text="Enable scheduled backup",
                        variable=self.schedule_enabled).pack(anchor='w', pady=5)
        ttk.Label(frm_sch, text="Interval (hours):").pack(anchor='w', pady=(10, 0))
        ttk.Spinbox(frm_sch, from_=1, to=168, textvariable=self.schedule_interval
                    ).pack(anchor='w')

        # Retention & Archive tab
        frm_ret = ttk.Frame(nb)
        nb.add(frm_ret, text="Retention & Archive")
        ttk.Label(frm_ret, text="Keep last N archives:").pack(anchor='w', pady=5)
        ttk.Spinbox(frm_ret, from_=1, to=100, textvariable=self.retention_count
                    ).pack(anchor='w')
        ttk.Label(frm_ret, text="Encryption Password (if enabled):"
                  ).pack(anchor='w', pady=5)
        ttk.Entry(frm_ret, textvariable=self.encryption_pwd, show='*'
                  ).pack(fill='x', padx=5)

        # Email notifications tab
        frm_email = ttk.Frame(nb)
        nb.add(frm_email, text="Email Notifications")
        for lbl, var, show in [
            ("SMTP Server:", self.smtp_server, False),
            ("Port:", self.smtp_port, False),
            ("User:", self.smtp_user, False),
            ("Password:", self.smtp_password, True),
            ("Notify To:", self.notify_email, False),
        ]:
            row = ttk.Frame(frm_email)
            row.pack(fill='x', pady=4)
            ttk.Label(row, text=lbl, width=15).pack(side='left')
            ttk.Entry(row, textvariable=var, width=30,
                      show='*' if show else '').pack(side='left')

        def _save_and_close():
            text = txt_ex.get('1.0', 'end').strip()
            self.exclude_patterns = text.split(';') if text else []
            self._save_config()
            self._reschedule()
            dlg.destroy()

        ttk.Button(dlg, text="Save Settings", command=_save_and_close
                   ).pack(pady=10)

    def _start_scheduler_if_enabled(self):
        """Initialize scheduler if enabled."""
        if self.schedule_enabled.get():
            self.scheduler.add_job(
                self._scheduled_backup, 'interval',
                hours=self.schedule_interval.get(), id='auto_backup'
            )
            self.scheduler.start()
            self._log(f"Scheduled backups every {self.schedule_interval.get()}h")

    def _reschedule(self):
        """Update scheduled job after settings change."""
        if self.scheduler.get_job('auto_backup'):
            self.scheduler.remove_job('auto_backup')
        if self.schedule_enabled.get():
            self.scheduler.add_job(
                self._scheduled_backup, 'interval',
                hours=self.schedule_interval.get(), id='auto_backup'
            )
            self._log(f"Rescheduled backups every {self.schedule_interval.get()}h")

    def _scheduled_backup(self):
        """Trigger backup via scheduler."""
        if self._task_thread and self._task_thread.is_alive():
            self._log("Previous backup still running; skipping this schedule.")
            return
        self._log("Scheduled backup started")
        self._start_backup()

    def _show_about(self):
        """Display the About dialog."""
        messagebox.showinfo(
            "About Backup & Sync Tool",
            "Version 1.1\nProfessional backup with scheduling, compression, "
            "encryption, retention, and email notifications."
        )

    def _on_exit(self):
        """Save config, shutdown scheduler, and exit."""
        self._save_config()
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)
        logging.info("Application exiting")
        self.destroy()


if __name__ == '__main__':
    BackupApp().mainloop()
