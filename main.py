# main.py

import os
import shutil
import threading
import time
import hashlib
import configparser
import logging
import queue
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk

CONFIG_PATH = 'config.ini'
LOG_PATH = 'backup.log'


def compute_sha256(path, block_size=65536):
    """
    Compute SHA-256 hash for a file.
    """
    sha = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha.update(block)
    return sha.hexdigest()


class BackupApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Backup & Sync Tool")
        self.geometry("700x550")
        self.resizable(False, False)

        # shared variables
        self.src_dir = tk.StringVar()
        self.dst_dir = tk.StringVar()
        self.delete_old = tk.BooleanVar(value=False)

        # internal state
        self._task_thread = None
        self._log_queue = queue.Queue()
        self._total_files = 0
        self._processed_files = 0

        self._load_config()
        self._setup_logging()
        self._build_menu()
        self._build_ui()
        self.after(100, self._flush_log_queue)

    def _setup_logging(self):
        """
        Configure file-based logging.
        """
        logging.basicConfig(
            filename=LOG_PATH,
            level=logging.INFO,
            format='%(asctime)s %(levelname)-8s %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        logging.info("Application started")

    def _load_config(self):
        """
        Load settings from INI file if available.
        """
        config = configparser.ConfigParser()
        if os.path.exists(CONFIG_PATH):
            config.read(CONFIG_PATH)
            self.src_dir.set(config.get('paths', 'src', fallback=''))
            self.dst_dir.set(config.get('paths', 'dst', fallback=''))
            self.delete_old.set(config.getboolean('options', 'delete_old', fallback=False))

    def _save_config(self):
        """
        Persist current settings to INI file.
        """
        config = configparser.ConfigParser()
        config['paths'] = {
            'src': self.src_dir.get(),
            'dst': self.dst_dir.get()
        }
        config['options'] = {
            'delete_old': str(self.delete_old.get())
        }
        with open(CONFIG_PATH, 'w') as cfg:
            config.write(cfg)
        logging.info("Settings saved to %s", CONFIG_PATH)

    def _build_menu(self):
        """
        Create application menu bar.
        """
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Exit", command=self._on_exit)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def _build_ui(self):
        """
        Construct all widgets in the main window.
        """
        padding = {'padx': 8, 'pady': 8}

        # Source selection
        ttk.Label(self, text="Source Directory:").grid(row=0, column=0, sticky='w', **padding)
        ttk.Entry(self, textvariable=self.src_dir, width=60).grid(row=0, column=1, **padding)
        ttk.Button(self, text="Browse…", command=self._browse_src).grid(row=0, column=2, **padding)

        # Destination selection
        ttk.Label(self, text="Destination Directory:").grid(row=1, column=0, sticky='w', **padding)
        ttk.Entry(self, textvariable=self.dst_dir, width=60).grid(row=1, column=1, **padding)
        ttk.Button(self, text="Browse…", command=self._browse_dst).grid(row=1, column=2, **padding)

        # Option: delete obsolete files
        ttk.Checkbutton(
            self,
            text="Delete files not present in source",
            variable=self.delete_old
        ).grid(row=2, column=1, sticky='w', **padding)

        # Start button
        self.start_btn = ttk.Button(self, text="Start Backup", command=self._start_backup)
        self.start_btn.grid(row=3, column=1, **padding)

        # Log area
        self.log_area = scrolledtext.ScrolledText(self, width=85, height=20, state='disabled')
        self.log_area.grid(row=4, column=0, columnspan=3, padx=10, pady=(0, 10))

        # Progress bar
        self.progress = ttk.Progressbar(self, orient='horizontal', length=650, mode='determinate')
        self.progress.grid(row=5, column=0, columnspan=3, padx=20, pady=(0, 10))

    def _browse_src(self):
        """
        Open directory chooser for source.
        """
        path = filedialog.askdirectory()
        if path:
            self.src_dir.set(path)

    def _browse_dst(self):
        """
        Open directory chooser for destination.
        """
        path = filedialog.askdirectory()
        if path:
            self.dst_dir.set(path)

    def _start_backup(self):
        """
        Validate inputs and launch backup thread.
        """
        src = self.src_dir.get()
        dst = self.dst_dir.get()

        if not os.path.isdir(src):
            messagebox.showerror("Invalid Path", "Source directory is not valid.")
            return

        if not os.path.isdir(dst):
            messagebox.showerror("Invalid Path", "Destination directory is not valid.")
            return

        # disable controls during backup
        self.start_btn.config(state='disabled')
        self._log(f"Initiating backup from\n  {src}\n  to\n  {dst}\nDelete obsolete: {self.delete_old.get()}")

        # launch background task
        args = (src, dst, self.delete_old.get())
        self._task_thread = threading.Thread(target=self._backup_task, args=args, daemon=True)
        self._task_thread.start()

    def _backup_task(self, src, dst, delete_old):
        """
        Perform incremental sync and optional deletion.
        """
        try:
            all_files = []
            for root, _, files in os.walk(src):
                for f in files:
                    all_files.append(os.path.join(root, f))
            self._total_files = len(all_files)
            self._processed_files = 0
            self.progress['maximum'] = self._total_files

            self._sync_directories(src, dst)

            if delete_old:
                self._delete_obsolete(dst, src)

            self._log("Backup completed successfully.")
            logging.info("Backup finished without errors.")
        except Exception as err:
            self._log(f"Unexpected error: {err}")
            logging.exception("Error during backup")
        finally:
            # re-enable controls
            self.start_btn.config(state='normal')

    def _sync_directories(self, src, dst):
        """
        Copy or update files based on SHA256 or modification time.
        """
        for root, _, files in os.walk(src):
            rel_path = os.path.relpath(root, src)
            target_root = os.path.join(dst, rel_path)
            os.makedirs(target_root, exist_ok=True)

            for fname in files:
                src_path = os.path.join(root, fname)
                dst_path = os.path.join(target_root, fname)

                try:
                    if os.path.exists(dst_path):
                        # compare size and timestamp before hashing
                        src_stat = os.stat(src_path)
                        dst_stat = os.stat(dst_path)
                        if src_stat.st_mtime == dst_stat.st_mtime and src_stat.st_size == dst_stat.st_size:
                            # skip copy when identical
                            self._advance_progress()
                            continue
                        # fallback to hash comparison for safety
                        if compute_sha256(src_path) == compute_sha256(dst_path):
                            self._advance_progress()
                            continue

                    shutil.copy2(src_path, dst_path)
                    os.utime(dst_path, (os.path.getatime(src_path), os.path.getmtime(src_path)))
                    self._log(f"Copied: {src_path} → {dst_path}")
                    logging.info("Copied %s to %s", src_path, dst_path)

                except Exception as exc:
                    self._log(f"Failed to copy {src_path}: {exc}")
                    logging.error("Copy error for %s: %s", src_path, exc)

                finally:
                    self._advance_progress()

    def _delete_obsolete(self, dst, src):
        """
        Remove files from destination that no longer exist in source.
        """
        self._log("Deleting obsolete items...")
        for root, dirs, files in os.walk(dst, topdown=False):
            rel_path = os.path.relpath(root, dst)
            src_root = os.path.join(src, rel_path)

            for fname in files:
                dst_file = os.path.join(root, fname)
                src_file = os.path.join(src_root, fname)
                if not os.path.exists(src_file):
                    try:
                        os.remove(dst_file)
                        self._log(f"Removed file: {dst_file}")
                        logging.info("Removed obsolete file %s", dst_file)
                    except Exception as exc:
                        self._log(f"Failed to remove {dst_file}: {exc}")
                        logging.error("Removal error for %s: %s", dst_file, exc)

            for d in dirs:
                dst_dir = os.path.join(root, d)
                if not os.listdir(dst_dir):
                    try:
                        os.rmdir(dst_dir)
                        self._log(f"Removed empty dir: {dst_dir}")
                        logging.info("Removed empty directory %s", dst_dir)
                    except Exception as exc:
                        self._log(f"Failed to remove dir {dst_dir}: {exc}")
                        logging.error("Dir removal error for %s: %s", dst_dir, exc)

    def _advance_progress(self):
        """
        Increment progress bar and update UI.
        """
        self._processed_files += 1
        self.progress['value'] = self._processed_files

    def _log(self, message):
        """
        Enqueue a timestamped message for the UI and file log.
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self._log_queue.put(f"[{timestamp}] {message}")
        logging.info(message)

    def _flush_log_queue(self):
        """
        Pull messages from queue and append to text widget.
        """
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

    def _show_about(self):
        """
        Display an About dialog.
        """
        messagebox.showinfo(
            "About Backup & Sync Tool",
            "Version 1.0\nA professional GUI for incremental backups."
        )

    def _on_exit(self):
        """
        Save settings and close application.
        """
        self._save_config()
        logging.info("Application exiting")
        self.destroy()


if __name__ == '__main__':
    app = BackupApp()
    app.mainloop()
