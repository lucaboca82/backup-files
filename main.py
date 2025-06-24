# main.py
import os
import shutil
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

class BackupGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Backup & Sync Tool")
        self.geometry("600x500")
        self.resizable(False, False)

        # Variables
        self.src_dir = tk.StringVar()
        self.dst_dir = tk.StringVar()
        self.delete_old = tk.BooleanVar(value=False)

        # Build UI
        self._build_widgets()

    def _build_widgets(self):
        pad = {'padx': 5, 'pady': 5}

        # Source
        tk.Label(self, text="Source Directory:").grid(row=0, column=0, sticky="w", **pad)
        tk.Entry(self, textvariable=self.src_dir, width= fifty).grid(row=0, column=1, **pad)
        tk.Button(self, text="Browse...", command=self._browse_src).grid(row=0, column=2, **pad)

        # Destination
        tk.Label(self, text="Destination Directory:").grid(row=1, column=0, sticky="w", **pad)
        tk.Entry(self, textvariable=self.dst_dir, width= fifty).grid(row=1, column=1, **pad)
        tk.Button(self, text="Browse...", command=self._browse_dst).grid(row=1, column=2, **pad)

        # Options
        tk.Checkbutton(self, text="Delete files not in source", variable=self.delete_old).grid(row=2, column=1, sticky="w", **pad)

        # Start button
        tk.Button(self, text="Start Backup", command=self._on_start, bg="#4CAF50", fg="white")\
            .grid(row=3, column=1, **pad)

        # Log area
        self.log = scrolledtext.ScrolledText(self, width=72, height=20, state='disabled')
        self.log.grid(row=4, column=0, columnspan=3, padx=10, pady=(0,10))

    def _browse_src(self):
        path = filedialog.askdirectory()
        if path:
            self.src_dir.set(path)

    def _browse_dst(self):
        path = filedialog.askdirectory()
        if path:
            self.dst_dir.set(path)

    def _on_start(self):
        src = self.src_dir.get()
        dst = self.dst_dir.get()
        if not os.path.isdir(src):
            messagebox.showerror("Error", "Source directory is invalid.")
            return
        if not os.path.isdir(dst):
            messagebox.showerror("Error", "Destination directory is invalid.")
            return
        # disable UI
        self._toggle_controls(state='disabled')
        self._log(f"Starting backup:\n  {src}\n  -> {dst}\nDelete old: {self.delete_old.get()}\n")
        threading.Thread(target=self._sync_task, args=(src, dst, self.delete_old.get()), daemon=True).start()

    def _sync_task(self, src, dst, delete_old):
        try:
            self._sync_folders(src, dst)
            if delete_old:
                self._delete_extra(dst, src)
            self._log("\nBackup completed successfully.")
        except Exception as e:
            self._log(f"\nError: {e}")
        finally:
            self._toggle_controls(state='normal')

    def _sync_folders(self, src, dst):
        for root, dirs, files in os.walk(src):
            rel = os.path.relpath(root, src)
            dst_root = os.path.join(dst, rel)
            if not os.path.exists(dst_root):
                os.makedirs(dst_root)
                self._log(f"Created directory: {dst_root}")

            for fname in files:
                src_path = os.path.join(root, fname)
                dst_path = os.path.join(dst_root, fname)
                try:
                    if (not os.path.exists(dst_path)) or (os.path.getmtime(src_path) > os.path.getmtime(dst_path)):
                        shutil.copy2(src_path, dst_path)
                        self._log(f"Copied: {src_path} -> {dst_path}")
                except Exception as exc:
                    self._log(f"Failed to copy {src_path}: {exc}")

    def _delete_extra(self, dst, src):
        self._log("\nDeleting files not in source...")
        for root, dirs, files in os.walk(dst, topdown=False):
            rel = os.path.relpath(root, dst)
            src_root = os.path.join(src, rel)
            for fname in files:
                dst_path = os.path.join(root, fname)
                src_path = os.path.join(src_root, fname)
                if not os.path.exists(src_path):
                    try:
                        os.remove(dst_path)
                        self._log(f"Removed file: {dst_path}")
                    except Exception as exc:
                        self._log(f"Failed to remove {dst_path}: {exc}")
            # remove empty dirs
            if not os.listdir(root):
                try:
                    os.rmdir(root)
                    self._log(f"Removed empty dir: {root}")
                except Exception as exc:
                    self._log(f"Failed to remove dir {root}: {exc}")

    def _toggle_controls(self, state='normal'):
        for child in self.winfo_children():
            if isinstance(child, (tk.Button, tk.Checkbutton)):
                child.config(state=state)

    def _log(self, msg: str):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log.configure(state='normal')
        self.log.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.log.see(tk.END)
        self.log.configure(state='disabled')

if __name__ == "__main__":
    app = BackupGUI()
    app.mainloop()
