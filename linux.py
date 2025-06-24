#!/usr/bin/env python3
import os
import shutil
import time
import hashlib
import logging
from logging.handlers import RotatingFileHandler
import fnmatch
import zipfile
import smtplib
import base64
import argparse
from email.message import EmailMessage
from cryptography.fernet import Fernet

LOG_PATH = 'backup.log'
BLOCK_SIZE = 65536


def compute_sha256(path):
    sha = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(BLOCK_SIZE), b''):
            sha.update(block)
    return sha.hexdigest()


def derive_key(password, salt=b'some_static_salt'):
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(dk)


def sync_directories(src, dst, excludes, log):
    total, done = 0, 0
    for root, _, files in os.walk(src):
        rel = os.path.relpath(root, src)
        if any(fnmatch.fnmatch(rel, pat) for pat in excludes):
            continue
        target = os.path.join(dst, rel)
        os.makedirs(target, exist_ok=True)
        for f in files:
            total += 1
            src_f = os.path.join(root, f)
            dst_f = os.path.join(target, f)
            if any(fnmatch.fnmatch(f, pat) for pat in excludes):
                done += 1; continue
            try:
                if os.path.exists(dst_f):
                    s, d = os.stat(src_f), os.stat(dst_f)
                    if s.st_mtime == d.st_mtime and s.st_size == d.st_size:
                        done += 1; continue
                    if compute_sha256(src_f) == compute_sha256(dst_f):
                        done += 1; continue
                shutil.copy2(src_f, dst_f)
                os.utime(dst_f, (os.path.getatime(src_f), os.path.getmtime(src_f)))
                log.info(f"Copied: {src_f} → {dst_f}")
            except Exception as e:
                log.error(f"Copy failed: {src_f}: {e}")
            done += 1
    return total


def delete_obsolete(dst, src, excludes, log):
    log.info("Removing obsolete items")
    for root, dirs, files in os.walk(dst, topdown=False):
        rel = os.path.relpath(root, dst)
        if any(fnmatch.fnmatch(rel, pat) for pat in excludes):
            continue
        src_root = os.path.join(src, rel)
        for f in files:
            dst_f = os.path.join(root, f)
            if not os.path.exists(os.path.join(src_root, f)):
                try:
                    os.remove(dst_f)
                    log.info(f"Removed: {dst_f}")
                except Exception as e:
                    log.error(f"Remove failed: {dst_f}: {e}")
        for d in dirs:
            path = os.path.join(root, d)
            if os.path.isdir(path) and not os.listdir(path):
                try:
                    os.rmdir(path)
                    log.info(f"Removed dir: {path}")
                except Exception as e:
                    log.error(f"Dir remove failed: {path}: {e}")


def compress_backup(dst, log):
    ts = time.strftime("%Y%m%d_%H%M%S")
    archive = os.path.join(dst, f"backup_{ts}.zip")
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(dst):
            for f in files:
                if f.endswith('.zip'): continue
                path = os.path.join(root, f)
                arc = os.path.relpath(path, dst)
                z.write(path, arc)
    log.info(f"Compressed to {archive}")
    return archive


def encrypt_archive(path, password, log):
    key = derive_key(password)
    f = Fernet(key)
    with open(path, 'rb') as fin:
        data = fin.read()
    token = f.encrypt(data)
    enc = path.replace('.zip', '_enc.bin')
    with open(enc, 'wb') as fout:
        fout.write(token)
    os.remove(path)
    log.info(f"Encrypted to {enc}")
    return enc


def apply_retention(folder, keep, log):
    pats = ['backup_*.zip', 'backup_*_enc.bin']
    for pat in pats:
        items = sorted([os.path.join(folder, f) for f in os.listdir(folder)
                        if fnmatch.fnmatch(f, pat)],
                       key=os.path.getmtime, reverse=True)
        for old in items[keep:]:
            try:
                os.remove(old)
                log.info(f"Removed old: {old}")
            except Exception as e:
                log.error(f"Retention remove failed: {old}: {e}")


def send_notification(smtp, port, user, pwd, to, attachment, log):
    try:
        msg = EmailMessage()
        msg['Subject'] = 'Backup Completed'
        msg['From'] = user
        msg['To'] = to
        msg.set_content(f"Backup finished at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        if attachment and os.path.exists(attachment):
            with open(attachment, 'rb') as f:
                data = f.read()
            msg.add_attachment(data, maintype='application', subtype='octet-stream',
                               filename=os.path.basename(attachment))
        s = smtplib.SMTP(smtp, port, timeout=30)
        s.starttls()
        s.login(user, pwd)
        s.send_message(msg)
        s.quit()
        log.info(f"Email sent to {to}")
    except Exception as e:
        log.error(f"Email failed: {e}")


def setup_logging():
    handler = RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=3)
    fmt = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s',
                            '%Y-%m-%d %H:%M:%S')
    handler.setFormatter(fmt)
    log = logging.getLogger('backup')
    log.setLevel(logging.INFO)
    log.addHandler(handler)
    return log


def parse_args():
    p = argparse.ArgumentParser(description='CLI backup for Linux')
    p.add_argument('--src', required=True, help='Source directory')
    p.add_argument('--dst', required=True, help='Destination directory')
    p.add_argument('--delete-old', action='store_true', help='Remove obsolete files')
    p.add_argument('--compress', action='store_true', help='Create ZIP archive')
    p.add_argument('--encrypt', action='store_true', help='Encrypt archive')
    p.add_argument('--password', help='Encryption password')
    p.add_argument('--retention', type=int, default=5, help='Keep last N archives')
    p.add_argument('--exclude', action='append', default=[], help='Exclude patterns')
    p.add_argument('--email', nargs=4,
                   metavar=('SMTP','PORT','USER','PWD','TO'),
                   help='Email settings: SMTP PORT USER PWD TO')
    return p.parse_args()


def main():
    args = parse_args()
    log = setup_logging()
    if args.encrypt and not args.password:
        log.error("Encryption requested but no password provided")
        return

    log.info(f"Starting backup: {args.src} → {args.dst}")
    t0 = time.time()
    sync_directories(args.src, args.dst, args.exclude, log)
    if args.delete_old:
        delete_obsolete(args.dst, args.src, args.exclude, log)

    archive = None
    if args.compress:
        archive = compress_backup(args.dst, log)
        if args.encrypt:
            archive = encrypt_archive(archive, args.password, log)

    apply_retention(args.dst if not archive else os.path.dirname(archive),
                    args.retention, log)

    if args.email:
        smtp, port, user, pwd, to = args.email
        send_notification(smtp, int(port), user, pwd, to, archive, log)

    dt = time.time() - t0
    log.info(f"Backup finished in {dt:.1f}s")


if __name__ == '__main__':
    main()
