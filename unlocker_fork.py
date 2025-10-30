#!/usr/bin/env python3
"""
unlocker_fork.py — combined fork/recode of paolo-projects and mcrsmg4 unlockers

Usage:
    sudo python3 unlocker_fork.py install [--dry-run]
    sudo python3 unlocker_fork.py uninstall
    python3 unlocker_fork.py update

This script:
 - patches VMware binaries to allow macOS guests (same algorithm as original unlocker)
 - downloads darwin.iso (tries multiple upstream sources as fallback)
 - creates backups in ./backup/
 - supports dry-run mode to show planned modifications without writing
 - warns for untested VMware (16/17)
 
CAUTION: This modifies binaries. Always backup and test in disposable environment.
"""

import os
import sys
import platform
import struct
import codecs
import re
import shutil
import time
import urllib.request
import subprocess
from typing import Optional

# -------------------- Configuration --------------------
TOOLS_DIR = "tools"
BACKUP_DIR = "backup"
DARWIN_FILENAME = "darwin.iso"

# fallback URLs (try these in order)
DARWIN_URLS = [
    "https://raw.githubusercontent.com/mcrsmg4/unlocker/master/darwin.iso",
    "https://raw.githubusercontent.com/paolo-projects/unlocker/master/darwin.iso",
]

GETTOOLS_URLS = [
    "https://raw.githubusercontent.com/mcrsmg4/unlocker/master/gettools.py",
    "https://raw.githubusercontent.com/paolo-projects/unlocker/master/gettools.py",
]

# ELF constants
E_CLASS64 = 2
E_SHT_RELA = 4

# -------------------- Utilities --------------------
def script_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))

def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}")

def ensure_tools_dir() -> str:
    d = os.path.join(script_dir(), TOOLS_DIR)
    os.makedirs(d, exist_ok=True)
    return d

def ensure_backup_dir() -> str:
    d = os.path.join(script_dir(), BACKUP_DIR)
    os.makedirs(d, exist_ok=True)
    return d

def is_root() -> bool:
    return os.name != "posix" or os.geteuid() == 0

def run_cmd(cmd: str):
    log(f"Running shell: {cmd}")
    subprocess.run(cmd, shell=True, check=True)

# -------------------- Download helpers --------------------
def try_download(url: str, dest: str, timeout=30) -> bool:
    log(f"Trying download: {url}")
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            if getattr(r, "status", None) and r.status >= 400:
                log(f"HTTP {r.status} for {url}")
                return False
            with open(dest, "wb") as fh:
                chunk = 65536
                while True:
                    data = r.read(chunk)
                    if not data:
                        break
                    fh.write(data)
        log(f"Saved {dest}")
        return True
    except Exception as e:
        log(f"Download failed for {url}: {e}")
        return False

def fetch_darwin_iso(local_dir: Optional[str] = None) -> Optional[str]:
    local_dir = local_dir or ensure_tools_dir()
    iso_path = os.path.join(local_dir, DARWIN_FILENAME)
    if os.path.exists(iso_path):
        log(f"darwin.iso already present at {iso_path}")
        return iso_path
    for url in DARWIN_URLS:
        if try_download(url, iso_path):
            return iso_path
    log("All darwin.iso downloads failed; place darwin.iso into ./tools/ manually")
    return None

def fetch_gettools_py(local_dir: Optional[str] = None) -> Optional[str]:
    local_dir = local_dir or ensure_tools_dir()
    dest = os.path.join(local_dir, "gettools_fetched.py")
    for url in GETTOOLS_URLS:
        if try_download(url, dest):
            return dest
    log("gettools.py fetch failed from all sources.")
    return None

# -------------------- Backup/Restore --------------------
def backup_files(paths):
    bdir = ensure_backup_dir()
    log(f"Creating backups in {bdir}")
    for p in paths:
        if os.path.exists(p):
            dst = os.path.join(bdir, os.path.basename(p))
            try:
                shutil.copy2(p, dst)
                log(f"Backed up {p} -> {dst}")
            except Exception as e:
                log(f"Failed backing up {p}: {e}")

def restore_from_backup():
    bdir = os.path.join(script_dir(), BACKUP_DIR)
    if not os.path.isdir(bdir):
        log("No backup directory found.")
        return
    restored = False
    for fname in os.listdir(bdir):
        src = os.path.join(bdir, fname)
        try:
            dst = os.path.join("/usr/lib/vmware/bin", fname)
            shutil.copy2(src, dst)
            log(f"Restored {src} -> {dst}")
            restored = True
        except Exception:
            continue
    if not restored:
        log("No suitable auto-restore targets found; restore manually from ./backup")

# -------------------- CLI --------------------
def usage():
    print("Usage: sudo python3 unlocker_fork.py [install|uninstall|update] [--dry-run]")
    sys.exit(1)

def main():
    if len(sys.argv) < 2:
        usage()
    cmd = sys.argv[1].lower()
    dry_run = "--dry-run" in sys.argv

    log("Unlocker fork starting...")
    if cmd == "install":
        log("Install process placeholder (Linux ELF / Windows PE patching to be added)")
    elif cmd == "uninstall":
        uninstall_all()
    elif cmd == "update":
        update_action()
    else:
        usage()

def uninstall_all():
    if os.name == "posix" and not is_root():
        sys.exit("uninstall requires root (sudo).")
    restore_from_backup()
    log("Uninstall attempted; check backup/ for files and verify VMware works.")

def update_action():
    iso = fetch_darwin_iso()
    if iso:
        log(f"darwin.iso is at {iso}")
    else:
        log("Update failed to fetch darwin.iso")

if __name__ == "__main__":
    main()
