#!/usr/bin/env python3
"""
unlocker_fork_full.py — Combined fork/recode with:
 - ELF vSMC patching including RELA relocation fix
 - GOS patching for vmwarebase .so
 - darwin.iso download + SHA256 verification (fetches official sha256 when available)
 - backup / restore (manifested)
 - Windows best-effort applesmc -> vmkernel patch + restore
 - CLI: install | uninstall | update, with --dry-run and --verify

Usage:
  sudo python3 unlocker_fork_full.py install [--dry-run] [--verify]
  sudo python3 unlocker_fork_full.py uninstall
  python3 unlocker_fork_full.py update [--verify]

WARNING: This script modifies VMware binaries. Test on disposable system first.
"""

from __future__ import print_function
import os
import sys
import platform
import struct
import codecs
import re
import shutil
import time
import urllib.request
import urllib.error
import json
import hashlib
import tempfile
import stat
import subprocess
from typing import Optional, List

# ---------------- Configuration ----------------

TOOLS_DIR = "tools"
BACKUP_DIR = "backup"
MANIFEST_FILE = "backup/manifest.json"
DARWIN_FILENAME = "darwin.iso"

# Candidate sources for darwin.iso and for a checksum file
DARWIN_RAW_GITHUB = "https://raw.githubusercontent.com/mcrsmg4/unlocker/master/darwin.iso"
DARWIN_RAW_PAOLO = "https://raw.githubusercontent.com/paolo-projects/unlocker/master/darwin.iso"

# Official frozen tools index (Broadcom) that contains a darwin.iso.sha256 file (best source)
BROADCOM_DARWIN_SHA256 = "https://packages-prod.broadcom.com/tools/frozen/darwin/darwin.iso.sha256"
BROADCOM_DARWIN_ISO = "https://packages-prod.broadcom.com/tools/frozen/darwin/darwin.iso"

# Fallback URL list (tries in order)
DARWIN_URLS = [BROADCOM_DARWIN_ISO, DARWIN_RAW_GITHUB, DARWIN_RAW_PAOLO]
DARWIN_SHA_URLS = [BROADCOM_DARWIN_SHA256]

# ELF constants
E_CLASS64 = 2
E_SHT_RELA = 4

# ---------------- Utilities ----------------

def now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")

def log(msg: str):
    print(f"[{now()}] {msg}")

def script_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))

def tools_dir() -> str:
    d = os.path.join(script_dir(), TOOLS_DIR)
    os.makedirs(d, exist_ok=True)
    return d

def backup_dir() -> str:
    d = os.path.join(script_dir(), BACKUP_DIR)
    os.makedirs(d, exist_ok=True)
    return d

def manifest_path() -> str:
    return os.path.join(script_dir(), MANIFEST_FILE)

def is_root() -> bool:
    if os.name == "posix":
        return os.geteuid() == 0
    elif os.name == "nt":
        # Windows: best-effort; assume elevated if running interactively as admin
        return True
    return False

def chmod_executable(path: str):
    try:
        st = os.stat(path)
        os.chmod(path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass

# ---------------- Networking: fetch ISO + checksum ----------------

def try_url_save(url: str, dest: str, timeout: int = 30) -> bool:
    log(f"Attempting download: {url}")
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
        log(f"Saved: {dest}")
        return True
    except Exception as e:
        log(f"Download failed: {e}")
        return False

def fetch_official_sha256() -> Optional[str]:
    """
    Try to fetch SHA256 text from Broadcom frozen index or other known locations.
    Expecting a small file that contains the SHA256 (maybe with filename).
    """
    for url in DARWIN_SHA_URLS:
        try:
            log(f"Trying to fetch official checksum from {url}")
            with urllib.request.urlopen(url, timeout=20) as r:
                text = r.read().decode(errors='ignore').strip()
                # file may contain "checksum  filename" or just checksum
                m = re.search(r'([a-fA-F0-9]{64})', text)
                if m:
                    sha = m.group(1)
                    log(f"Found official SHA256: {sha}")
                    return sha
                else:
                    log(f"No SHA256 token found in response from {url}")
        except Exception as e:
            log(f"Could not fetch {url}: {e}")
    return None

def download_darwin_iso(dest: str, verify_sha: Optional[str] = None, dry_run: bool = False) -> Optional[str]:
    """
    Downloads darwin.iso into dest (full path). Returns path on success, None on failure.
    If verify_sha given, verifies computed SHA256 equals it.
    """
    if os.path.exists(dest):
        log(f"{dest} already exists")
        if verify_sha:
            ok = verify_sha256(dest, verify_sha)
            if not ok:
                log("Existing ISO checksum mismatch; will redownload.")
                os.remove(dest)
            else:
                return dest
        else:
            return dest

    if dry_run:
        log(f"(dry-run) would download darwin.iso to {dest}")
        return dest

    for url in DARWIN_URLS:
        try:
            if try_url_save(url, dest):
                if verify_sha:
                    if not verify_sha256(dest, verify_sha):
                        log("Downloaded ISO checksum mismatch; removing and trying next source.")
                        os.remove(dest)
                        continue
                return dest
        except Exception:
            continue
    return None

def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def verify_sha256(path: str, expected_sha: str) -> bool:
    try:
        actual = compute_sha256(path)
        log(f"Computed SHA256: {actual}")
        ok = actual.lower() == expected_sha.lower()
        if ok:
            log("SHA256 verification: OK")
        else:
            log(f"SHA256 verification: FAIL (expected {expected_sha})")
        return ok
    except Exception as e:
        log(f"Checksum verify error: {e}")
        return False

# ---------------- Backup / restore ----------------

def save_manifest(manifest: dict):
    p = manifest_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        json.dump(manifest, fh, indent=2)

def load_manifest() -> dict:
    p = manifest_path()
    if not os.path.exists(p):
        return {}
    with open(p, "r") as fh:
        return json.load(fh)

def record_backup(orig_path: str):
    """
    Copy orig_path into backup dir and record mapping in manifest.
    """
    bdir = backup_dir()
    manifest = load_manifest()
    if not os.path.exists(orig_path):
        log(f"Cannot backup missing file: {orig_path}")
        return
    filename = os.path.basename(orig_path)
    dst = os.path.join(bdir, filename)
    # If we already have a backup, don't overwrite (preserve original)
    if not os.path.exists(dst):
        try:
            shutil.copy2(orig_path, dst)
            log(f"Backed up {orig_path} -> {dst}")
            manifest[filename] = orig_path
            save_manifest(manifest)
        except Exception as e:
            log(f"Backup failed for {orig_path}: {e}")
    else:
        log(f"Backup for {orig_path} already exists at {dst}")

def restore_from_manifest(dry_run: bool = False):
    manifest = load_manifest()
    if not manifest:
        log("No backup manifest found.")
        return
    restored = False
    for name, orig in manifest.items():
        src = os.path.join(backup_dir(), name)
        if not os.path.exists(src):
            log(f"Manifest entry missing source backup: {src}")
            continue
        try:
            if dry_run:
                log(f"(dry-run) Would restore {src} -> {orig}")
            else:
                os.makedirs(os.path.dirname(orig), exist_ok=True)
                shutil.copy2(src, orig)
                log(f"Restored {src} -> {orig}")
                restored = True
        except Exception as e:
            log(f"Restore failed {src} -> {orig}: {e}")
    if not restored:
        log("No files restored automatically; inspect backup/ manually if needed.")

# ---------------- Original Unlocker core (ported) ----------------

def bytetohex(data: bytes) -> str:
    return "".join("{:02X} ".format(c) for c in data)

def set_bit(value: int, bit: int) -> int:
    return value | (1 << bit)

def patchelf(f, oldoffset, newoffset):
    f.seek(0)
    magic = f.read(4)
    if magic != b'\x7fELF':
        raise Exception('Magic number does not match')

    ei_class = struct.unpack('=B', f.read(1))[0]
    if ei_class != E_CLASS64:
        raise Exception('Not 64bit elf header')

    f.seek(40)
    e_shoff = struct.unpack('=Q', f.read(8))[0]
    f.seek(58)
    e_shentsize = struct.unpack('=H', f.read(2))[0]
    e_shnum = struct.unpack('=H', f.read(2))[0]
    e_shstrndx = struct.unpack('=H', f.read(2))[0]

    log('e_shoff: 0x{:x} e_shentsize: 0x{:x} e_shnum:0x{:x} e_shstrndx:0x{:x}'.format(e_shoff, e_shentsize, e_shnum, e_shstrndx))

    for i in range(0, e_shnum):
        f.seek(e_shoff + i * e_shentsize)
        e_sh = struct.unpack('=LLQQQQLLQQ', f.read(e_shentsize))
        e_sh_type = e_sh[1]
        e_sh_offset = e_sh[4]
        e_sh_size = e_sh[5]
        e_sh_entsize = e_sh[9]
        if e_sh_type == E_SHT_RELA:
            e_sh_nument = int(e_sh_size / e_sh_entsize)
            for j in range(0, e_sh_nument):
                f.seek(e_sh_offset + e_sh_entsize * j)
                rela = struct.unpack('=QQq', f.read(e_sh_entsize))
                r_offset = rela[0]
                r_info = rela[1]
                r_addend = rela[2]
                if r_addend == oldoffset:
                    r_addend = newoffset
                    f.seek(e_sh_offset + e_sh_entsize * j)
                    f.write(struct.pack('=QQq', r_offset, r_info, r_addend))
                    log('Relocation modified at: ' + hex(e_sh_offset + e_sh_entsize * j))

def patchkeys(f, key):
    key_pack = '=4sB4sB6xQ'
    smc_new_memptr = 0
    i = 0
    while True:
        offset = key + (i * 72)
        f.seek(offset)
        try:
            smc_key = struct.unpack(key_pack, f.read(24))
        except struct.error:
            raise Exception("Failed to read SMC key struct - file may be truncated or format changed")
        smc_data = f.read(smc_key[1])
        f.seek(offset)
        if smc_key[0] == b'SKL+':
            smc_new_memptr = smc_key[4]
            log('+LKS Key:')
        elif smc_key[0] == b'0KSO':
            log('OSK0 Key Before:')
            f.seek(offset)
            f.write(struct.pack(key_pack, smc_key[0], smc_key[1], smc_key[2], smc_key[3], smc_new_memptr))
            f.flush()
            f.seek(offset + 24)
            smc_new_data = codecs.encode('bheuneqjbexolgurfrjbeqfthneqrqcy', 'rot_13')
            f.write(smc_new_data.encode('UTF-8'))
            f.flush()
            log('OSK0 Key After:')
        elif smc_key[0] == b'1KSO':
            log('OSK1 Key Before:')
            smc_old_memptr = smc_key[4]
            f.seek(offset)
            f.write(struct.pack(key_pack, smc_key[0], smc_key[1], smc_key[2], smc_key[3], smc_new_memptr))
            f.flush()
            f.seek(offset + 24)
            smc_new_data = codecs.encode('rnfrqbagfgrny(p)NccyrPbzchgreVap', 'rot_13')
            f.write(smc_new_data.encode('UTF-8'))
            f.flush()
            log('OSK1 Key After:')
            return smc_old_memptr, smc_new_memptr
        i += 1

def patchsmc(name: str, sharedobj: bool, dry_run: bool = False):
    log('File: ' + name + '\n')
    with open(name, 'r+b') as f:
        vmx = f.read()
        smc_header_v0 = b'\xF2\x00\x00\x00\xF0\x00\x00\x00'
        smc_header_v1 = b'\xB4\x01\x00\x00\xB0\x01\x00\x00'
        key_key = b'\x59\x45\x4B\x23\x04\x32\x33\x69\x75'
        adr_key = b'\x72\x64\x41\x24\x04\x32\x33\x69\x75'
        smc_header_v0_offset = vmx.find(smc_header_v0) - 8
        smc_header_v1_offset = vmx.find(smc_header_v1) - 8
        smc_key0 = vmx.find(key_key)
        smc_key1 = vmx.rfind(key_key)
        smc_adr = vmx.find(adr_key)
        log('appleSMCTableV0 (smc.version = "0")')
        log('appleSMCTableV0 Address      : ' + hex(smc_header_v0_offset))
        if (smc_adr - smc_key0) != 72:
            log('appleSMCTableV0 Table        : ' + hex(smc_key0))
            if not dry_run:
                smc_old_memptr, smc_new_memptr = patchkeys(f, smc_key0)
        elif (smc_adr - smc_key1) != 72:
            log('appleSMCTableV0 Table        : ' + hex(smc_key1))
            if not dry_run:
                smc_old_memptr, smc_new_memptr = patchkeys(f, smc_key1)
        else:
            smc_old_memptr = smc_new_memptr = 0

        log('appleSMCTableV1 (smc.version = "1")')
        log('appleSMCTableV1 Address      : ' + hex(smc_header_v1_offset))
        if (smc_adr - smc_key0) == 72:
            log('appleSMCTableV1 Table        : ' + hex(smc_key0))
            if not dry_run:
                smc_old_memptr, smc_new_memptr = patchkeys(f, smc_key0)
        elif (smc_adr - smc_key1) == 72:
            log('appleSMCTableV1 Table        : ' + hex(smc_key1))
            if not dry_run:
                smc_old_memptr, smc_new_memptr = patchkeys(f, smc_key1)
        if sharedobj and not dry_run:
            log('Modifying RELA records from: ' + hex(smc_old_memptr) + ' to ' + hex(smc_new_memptr))
            patchelf(f, smc_old_memptr, smc_new_memptr)
    log('Finished patchsmc for ' + name)

def patchbase(name: str, dry_run: bool = False):
    log('GOS Patching: ' + name)
    with open(name, 'r+b') as f:
        base = f.read()
        darwin = re.compile(
                 b'\x10\x00\x00\x00[\x10|\x20]\x00\x00\x00[\x01|\x02]\x00\x00\x00\x00\x00\x00\x00'
                 b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        for m in darwin.finditer(base):
            offset = m.start()
            if dry_run:
                log(f"(dry-run) Would patch GOS flag at {hex(offset)}")
            else:
                f.seek(offset + 32)
                flag = f.read(1)[0]
                flag = set_bit(flag, 0)
                f.seek(offset + 32)
                f.write(bytes([flag]))
                log('GOS Patched flag @: ' + hex(offset))
        f.flush()
    log('GOS Patched: ' + name)

def patchvmkctl(name: str, dry_run: bool = False):
    log('smcPresent Patching: ' + name)
    with open(name, 'r+b') as f:
        vmkctl = f.read()
        applesmc = vmkctl.find(b'applesmc')
        if applesmc == -1:
            log("applesmc not found in file (skipping).")
            return
        if dry_run:
            log(f"(dry-run) Would replace 'applesmc' at offset {hex(applesmc)}")
            return
        f.seek(applesmc)
        f.write(b'vmkernel')
        f.flush()
    log('smcPresent Patched: ' + name)

# -------------------- High-level flows --------------------

def detect_vmware_version() -> Optional[str]:
    try:
        out = subprocess.check_output(["vmware", "-v"], stderr=subprocess.STDOUT, text=True)
        m = re.search(r'(\d+\.\d+(?:\.\d+)?)', out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None

def get_linux_targets():
    vmx = "/usr/lib/vmware/bin/vmware-vmx"
    vmx_debug = "/usr/lib/vmware/bin/vmware-vmx-debug"
    vmx_stats = "/usr/lib/vmware/bin/vmware-vmx-stats"
    lib_candidates = [
        "/usr/lib/vmware/lib/libvmwarebase.so/libvmwarebase.so",
        "/usr/lib/vmware/lib/libvmwarebase.so.0/libvmwarebase.so.0"
    ]
    return [vmx, vmx_debug, vmx_stats], lib_candidates

def get_windows_targets():
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    vmx = os.path.join(pf86, "VMware\\VMware Workstation\\vmware-vmx.exe")
    vmx_alt = os.path.join(pf, "VMware\\VMware Workstation\\vmware-vmx.exe")
    vmwarebase = os.path.join(pf86, "VMware\\VMware Workstation\\vmwarebase.dll")
    return [vmx, vmx_alt], [vmwarebase]

def install_all(dry_run: bool = False, verify: bool = False):
    # detect version
    v = detect_vmware_version()
    if v:
        log(f"Detected VMware version: {v}")
        try:
            major = int(v.split('.')[0])
            if major >= 16:
                log("Warning: VMware 16+ is untested. Proceed with caution.")
        except Exception:
            pass

    system = platform.system()
    manifest = {}

    if system == "Linux":
        if not is_root():
            sys.exit("install requires root (sudo).")
        vmx_candidates, lib_candidates = get_linux_targets()
        # collect existing files
        existing = [p for p in vmx_candidates + lib_candidates if os.path.isfile(p)]
        if existing:
            log("Backing up existing VMware files...")
            for p in existing:
                record_backup(p)
        else:
            log("Warning: no typical VMware binaries found. If VMware is installed elsewhere, edit script.")

        # Patch vmx files
        for vmx in vmx_candidates:
            if os.path.isfile(vmx):
                try:
                    # patch SMC & RELA (sharedobj True if lib exists)
                    sharedobj = any(os.path.isfile(c) for c in lib_candidates)
                    log(f"Patching SMC in {vmx} (sharedobj={sharedobj})")
                    patchsmc(vmx, sharedobj, dry_run=dry_run)
                except Exception as e:
                    log(f"Error patching {vmx}: {e}")

        # Patch vmwarebase / GOS flags
        for lib in lib_candidates:
            if os.path.isfile(lib):
                try:
                    patchbase(lib, dry_run=dry_run)
                except Exception as e:
                    log(f"Error patching {lib}: {e}")

        # patch vmkctl if present
        # Try common locations for vmkctl style; optional
        # (not usually present on Workstation)

        # Download and install darwin.iso
        tools = tools_dir()
        sha = fetch_official_sha256()
        iso_path = os.path.join(tools, DARWIN_FILENAME)
        downloaded = download_darwin_iso(iso_path, verify_sha=sha, dry_run=dry_run)
        if downloaded and not dry_run:
            # copy to VMware iso dir
            tgt = "/usr/lib/vmware/isoimages"
            try:
                os.makedirs(tgt, exist_ok=True)
                dst = os.path.join(tgt, os.path.basename(downloaded))
                shutil.copy2(downloaded, dst)
                log(f"Copied darwin.iso to {dst}")
            except Exception as e:
                log(f"Failed to copy darwin.iso to {tgt}: {e}")

    elif system == "Windows":
        # Best-effort: backup and patch "applesmc" occurrences
        vmx_list, lib_list = get_windows_targets()
        existing = [p for p in vmx_list + lib_list if os.path.isfile(p)]
        if existing:
            log("Backing up existing VMware files (Windows)...")
            for p in existing:
                record_backup(p)
        else:
            log("No VMware files found in expected Windows locations.")

        for p in existing:
            try:
                # patch applesmc -> vmkernel if found
                with open(p, "r+b") as fh:
                    data = fh.read()
                    i = data.find(b"applesmc")
                    if i == -1:
                        log(f"No applesmc found in {p}; skipping.")
                        continue
                    if dry_run:
                        log(f"(dry-run) Would replace applesmc at offset {hex(i)} in {p}")
                        continue
                    fh.seek(i)
                    fh.write(b"vmkernel")
                    log(f"Patched applesmc -> vmkernel in {p}")
            except Exception as e:
                log(f"Windows patch error for {p}: {e}")

        # Download and copy darwin.iso into VMware isoimages folder on Windows
        tools = tools_dir()
        sha = fetch_official_sha256()
        iso_path = os.path.join(tools, DARWIN_FILENAME)
        downloaded = download_darwin_iso(iso_path, verify_sha=sha, dry_run=dry_run)
        if downloaded and not dry_run:
            # copy to program files path
            pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
            tgt = os.path.join(pf86, "VMware\\VMware Workstation\\isoimages")
            try:
                os.makedirs(tgt, exist_ok=True)
                dst = os.path.join(tgt, os.path.basename(downloaded))
                shutil.copy2(downloaded, dst)
                log(f"Copied darwin.iso to {dst}")
            except Exception as e:
                log(f"Failed to copy darwin.iso to {tgt}: {e}")

    else:
        sys.exit("Unsupported OS for install")

    log("Install flow complete (dry-run was {})".format(dry_run))

def uninstall_all(dry_run: bool = False):
    if os.name == "posix" and not is_root():
        sys.exit("uninstall requires root (sudo).")
    restore_from_manifest(dry_run=dry_run)
    log("Uninstall/restore attempted.")

def update_action(verify_flag: bool = False, dry_run: bool = False):
    sha = fetch_official_sha256()
    tools = tools_dir()
    iso_path = os.path.join(tools, DARWIN_FILENAME)
    downloaded = download_darwin_iso(iso_path, verify_sha=sha, dry_run=dry_run)
    if downloaded:
        log(f"darwin.iso available at {downloaded}")
    else:
        log("Failed to download darwin.iso from all sources.")

# -------------------- CLI --------------------

def usage_and_exit():
    print("Usage: sudo python3 unlocker_fork_full.py [install|uninstall|update] [--dry-run] [--verify]")
    sys.exit(1)

def main():
    if len(sys.argv) < 2:
        usage_and_exit()
    cmd = sys.argv[1].lower()
    dry_run = "--dry-run" in sys.argv
    verify_flag = "--verify" in sys.argv

    log("Unlocker fork (full) starting...")
    v = detect_vmware_version()
    if v:
        log(f"Detected VMware version: {v}")
    else:
        log("Could not detect VMware version automatically.")

    if cmd == "install":
        install_all(dry_run=dry_run, verify=verify_flag)
    elif cmd == "uninstall":
        uninstall_all(dry_run=dry_run)
    elif cmd == "update":
        update_action(verify_flag=verify_flag, dry_run=dry_run)
    else:
        usage_and_exit()

if __name__ == "__main__":
    main()
