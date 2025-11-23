from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    psutil = None  # type: ignore


BUFFER_SIZE = 1024 * 1024  # 1 MiB chunks
SAFETY_BUFFER = 64 * 1024 * 1024  # leave ~64 MiB free to avoid OS issues
# Maximum single file size to avoid FAT32 4 GiB limits (use 3.5 GiB safety)
MAX_FILE_SIZE = (7 * 1024 * 1024 * 1024) // 2  # 3.5 GiB


def human_bytes(n: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    size = float(n)
    for u in units:
        if size < 1024 or u == units[-1]:
            return f"{size:.2f} {u}"
        size /= 1024


@dataclass
class DriveInfo:
    mount: str
    device: str
    fstype: Optional[str]
    total: int
    free: int
    vendor: Optional[str] = None
    model: Optional[str] = None
    removable: Optional[bool] = None


def list_drives() -> List[DriveInfo]:
    drives: List[DriveInfo] = []
    if psutil is not None:
        parts = psutil.disk_partitions(all=False)
        for p in parts:
            try:
                usage = shutil.disk_usage(p.mountpoint)
            except Exception:
                continue
            drives.append(
                DriveInfo(
                    mount=p.mountpoint,
                    device=p.device,
                    fstype=p.fstype or None,
                    total=usage.total,
                    free=usage.free,
                )
            )
    else:
        # Fallback POSIX using 'mount' output
        if os.name != "nt":
            try:
                out = subprocess.check_output(["mount"], text=True, stderr=subprocess.DEVNULL)
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 3:
                        device = parts[0]
                        mountpoint = parts[2]
                        try:
                            usage = shutil.disk_usage(mountpoint)
                        except Exception:
                            continue
                        fstype = None
                        if "type" in parts:
                            try:
                                fstype = parts[parts.index("type") + 1]
                            except Exception:
                                pass
                        drives.append(DriveInfo(mount=mountpoint, device=device, fstype=fstype, total=usage.total, free=usage.free))
            except Exception:
                pass
        else:
            # Windows fallback: list common drive letters
            from string import ascii_uppercase

            for letter in ascii_uppercase:
                root = f"{letter}:/"
                if os.path.exists(root):
                    try:
                        usage = shutil.disk_usage(root)
                        drives.append(DriveInfo(mount=root, device=root, fstype=None, total=usage.total, free=usage.free))
                    except Exception:
                        continue

    # On macOS, only show drives mounted under /Volumes
    try:
        if platform.system().lower() == "darwin":
            drives = [d for d in drives if os.path.abspath(d.mount).startswith("/Volumes/")]
    except Exception:
        # If platform check fails, leave list as-is
        pass

    # Enrich with vendor/model when possible
    for d in drives:
        v, m, rem = detect_vendor_model(d)
        d.vendor, d.model, d.removable = v, m, rem
    return drives


def detect_vendor_model(d: DriveInfo) -> Tuple[Optional[str], Optional[str], Optional[bool]]:
    system = platform.system().lower()
    try:
        if system == "linux":
            # Map device like /dev/sdb1 -> sdb
            base = os.path.basename(d.device)
            # handle mapper and partitions
            if base.startswith("sd") or base.startswith("hd") or base.startswith("nvme"):
                block = base.split("p")[0].rstrip("0123456789") if base.startswith("nvme") else base.rstrip("0123456789")
            else:
                block = base
            sys_path = f"/sys/block/{block}/device"
            vend = _safe_read(os.path.join(sys_path, "vendor"))
            model = _safe_read(os.path.join(sys_path, "model"))
            removable = _safe_read(os.path.join(f"/sys/block/{block}", "removable"))
            rem = None
            if removable is not None:
                rem = removable.strip() == "1"
            return _clean(vend), _clean(model), rem
        if system == "darwin":  # macOS
            # Use diskutil info
            try:
                out = subprocess.check_output(["diskutil", "info", d.mount], text=True)
            except Exception:
                try:
                    out = subprocess.check_output(["diskutil", "info", d.device], text=True)
                except Exception:
                    return None, None, None
            vendor = None
            model = None
            rem = None
            for line in out.splitlines():
                if ":" in line:
                    k, v = [x.strip() for x in line.split(":", 1)]
                    if k in ("Device / Media Name", "Device / Media Identifier", "Media Name"):
                        model = v
                    if k in ("Device Location", "Removable Media"):
                        if v.lower() in ("external", "removable"):
                            rem = True
                        elif v.lower() in ("internal", "fixed"):
                            rem = False
            return vendor, model, rem
        if system == "windows":
            # Try PowerShell Get-Volume and Get-PhysicalDisk (best-effort)
            try:
                # Map mount (like E:\\) to FriendlyName
                script = (
                    "Get-Volume | Select-Object DriveLetter,FileSystemLabel,FileSystem,Size,SizeRemaining | ConvertTo-Json"
                )
                out = subprocess.check_output(["powershell", "-NoProfile", "-Command", script], text=True)
                import json as _json  # local alias

                vols = _json.loads(out)
                if isinstance(vols, dict):
                    vols = [vols]
                root = d.mount.replace("/", "\\").upper()
                if len(root) >= 2 and root[1] == ":":
                    letter = root[0]
                else:
                    letter = None
                label = None
                if letter:
                    for v in vols:
                        if v.get("DriveLetter") and str(v.get("DriveLetter")).upper() == letter:
                            label = v.get("FileSystemLabel")
                            break
                return label, None, None
            except Exception:
                return None, None, None
    except Exception:
        return None, None, None
    return None, None, None


def _safe_read(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read().strip()
    except Exception:
        return None


def _clean(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    return " ".join(s.split()) or None


def is_blocked_system_drive(path: str, device: Optional[str]) -> bool:
    system = platform.system().lower()
    norm = os.path.abspath(path)
    if system == "windows":
        root = os.path.splitdrive(norm)[0].upper()
        return root.startswith("C:")
    if system == "darwin":
        # Block root and internal disk0
        if norm == "/":
            return True
        if device and "disk0" in device:
            return True
        return False
    else:  # linux/other posix
        if norm == "/":
            return True
        if device and device.startswith("/dev/sda"):
            return True
        return False


def confirm_destruction(target: str) -> bool:
    print("WARNING: The selected drive will be COMPLETELY WIPED as part of this health check.")
    print(f"Target: {target}")
    print("This operation is DESTRUCTIVE and IRREVERSIBLE. Type 'YES' to proceed: ", end="", flush=True)
    try:
        resp = input().strip()
    except EOFError:
        return False
    return resp == "YES"


def print_drive_info(info: DriveInfo) -> None:
    print("Drive information:")
    print(f"  Mount:       {info.mount}")
    print(f"  Device:      {info.device}")
    if info.fstype:
        print(f"  Filesystem:  {info.fstype}")
    if info.vendor:
        print(f"  Vendor:      {info.vendor}")
    if info.model:
        print(f"  Model:       {info.model}")
    if info.removable is not None:
        print(f"  Removable:   {info.removable}")
    print(f"  Size:        {human_bytes(info.total)}")
    print(f"  Free:        {human_bytes(info.free)}")


def _progress(prefix: str, done: int, total: int, last_print: float, min_interval: float = 0.5) -> float:
    now = time.time()
    if now - last_print >= min_interval or done >= total:
        pct = (done / total * 100.0) if total > 0 else 100.0
        print(f"\r{prefix}: {pct:6.2f}%", end="", flush=True)
        return now
    return last_print


def _write_pattern_file(dir_path: str, filename: str, total_bytes: int, pattern: Optional[bytes], random_mode: bool, compute_hash: bool = False) -> Optional[str]:
    """Write a file with either fixed pattern or random bytes.

    Returns hex digest if compute_hash is True, else None.
    """
    hasher = hashlib.sha256() if compute_hash else None
    # Enforce maximum single-file size (3.5 GiB)
    if total_bytes > MAX_FILE_SIZE:
        total_bytes = MAX_FILE_SIZE
    written = 0
    path = os.path.join(dir_path, filename)
    last_print = 0.0
    try:
        with open(path, "wb", buffering=0) as f:
            while written < total_bytes:
                chunk = min(BUFFER_SIZE, total_bytes - written)
                if random_mode:
                    data = os.urandom(chunk)
                else:
                    if pattern is None:
                        data = b"\x00" * chunk
                    else:
                        if len(pattern) == 1:
                            data = pattern * chunk
                        else:
                            # tile
                            reps = (chunk + len(pattern) - 1) // len(pattern)
                            data = (pattern * reps)[:chunk]
                f.write(data)
                if hasher:
                    hasher.update(data)
                written += len(data)
                last_print = _progress("Writing", written, total_bytes, last_print)
    finally:
        print()
    return hasher.hexdigest() if hasher else None


def _hash_file(path: str, total_bytes: int) -> str:
    hasher = hashlib.sha256()
    read = 0
    last_print = 0.0
    with open(path, "rb", buffering=0) as f:
        while True:
            data = f.read(BUFFER_SIZE)
            if not data:
                break
            hasher.update(data)
            read += len(data)
            last_print = _progress("Reading ", min(read, total_bytes), total_bytes, last_print)
    print()
    return hasher.hexdigest()


def run_health_check(target_mount: str, force: bool = False) -> int:
    # Identify drive info
    selected: Optional[DriveInfo] = None
    for d in list_drives():
        if os.path.abspath(d.mount) == os.path.abspath(target_mount):
            selected = d
            break
    if selected is None:
        # Fallback: construct from path
        try:
            usage = shutil.disk_usage(target_mount)
        except FileNotFoundError:
            print(f"Error: target path not found: {target_mount}")
            return 2
        selected = DriveInfo(mount=os.path.abspath(target_mount), device=target_mount, fstype=None, total=usage.total, free=usage.free)
        v, m, r = detect_vendor_model(selected)
        selected.vendor, selected.model, selected.removable = v, m, r

    if is_blocked_system_drive(selected.mount, selected.device):
        print("Refusing to run on a system drive. Choose a removable USB flash drive instead.")
        return 3

    print_drive_info(selected)

    if not force:
        if not confirm_destruction(selected.mount):
            print("Operation cancelled by user.")
            return 1

    # Decide test file size: aim to use nearly all capacity but leave a safety buffer
    # Prefer to use total size minus SAFETY_BUFFER, but not exceed free space minus SAFETY_BUFFER
    usage = shutil.disk_usage(selected.mount)
    target_size = max(0, min(usage.total - SAFETY_BUFFER, usage.free - SAFETY_BUFFER, MAX_FILE_SIZE))
    # Ensure at least some minimal size
    if target_size < 8 * 1024 * 1024:
        print("Not enough free space to run tests safely (need at least 8 MiB free).")
        return 4

    tmp_dir = selected.mount
    test_file = os.path.join(tmp_dir, ".flash_check_test.bin")

    def safe_unlink(p: str) -> None:
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
        except Exception:
            pass

    # 0) Initial zeroing pass
    print("Step 0: Initial wipe (zero fill)...")
    try:
        _ = _write_pattern_file(tmp_dir, ".flash_check_zero.tmp", target_size, b"\x00", random_mode=False)
    except Exception as e:
        print(f"Error during zero wipe: {e}")
        safe_unlink(os.path.join(tmp_dir, ".flash_check_zero.tmp"))
        return 5
    safe_unlink(os.path.join(tmp_dir, ".flash_check_zero.tmp"))
    print("Zero wipe complete.")

    # 1) Fill with 0xFF (ones) then delete
    print("Step 1: Full fill with 0xFF (ones)...")
    try:
        _ = _write_pattern_file(tmp_dir, os.path.basename(test_file), target_size, b"\xFF", random_mode=False)
    except Exception as e:
        print(f"Error during 0xFF fill: {e}")
        safe_unlink(test_file)
        return 6
    print("Step 1: Wiping test data...")
    safe_unlink(test_file)
    print("Step 1 complete.")

    # 2) Random fill with hash verify
    print("Step 2: Random fill with hash verify (write)...")
    try:
        write_hash = _write_pattern_file(tmp_dir, os.path.basename(test_file), target_size, None, random_mode=True, compute_hash=True)
    except Exception as e:
        print(f"Error during random fill: {e}")
        safe_unlink(test_file)
        return 7
    if not write_hash:
        print("Internal error: missing write hash")
        safe_unlink(test_file)
        return 8
    print(f"Write hash: {write_hash}")

    print("Step 2: Verifying by re-reading and hashing...")
    try:
        read_hash = _hash_file(test_file, target_size)
    except Exception as e:
        print(f"Error during verification read: {e}")
        safe_unlink(test_file)
        return 9
    print(f"Read  hash: {read_hash}")

    if read_hash != write_hash:
        print("ALERT: Hash mismatch! The drive failed the random data verification test.")
        safe_unlink(test_file)
        return 10

    print("Step 2: Wiping test data...")
    safe_unlink(test_file)

    print("SUCCESS: All tests completed successfully.")
    return 0


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="USB flash drive health checker (DESTRUCTIVE)")
    parser.add_argument("--list", action="store_true", help="List available drives and exit")
    parser.add_argument("--drive", help="Target drive mount path (e.g., E:\\, /Volumes/USB, or /media/usb)")
    parser.add_argument("--force", action="store_true", help="Skip confirmation prompt (DANGEROUS)")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.list:
        drives = list_drives()
        if not drives:
            print("No drives found.")
            return 0
        print("Available drives:")
        for d in drives:
            parts = [
                f"Mount={d.mount}",
                f"Device={d.device}",
                f"Size={human_bytes(d.total)}",
                f"Free={human_bytes(d.free)}",
            ]
            if d.vendor:
                parts.append(f"Vendor={d.vendor}")
            if d.model:
                parts.append(f"Model={d.model}")
            if d.removable is not None:
                parts.append(f"Removable={d.removable}")
            print("  - " + ", ".join(parts))
        return 0

    if not args.drive:
        parser.print_help()
        return 0

    return run_health_check(args.drive, force=args.force)


if __name__ == "__main__":
    sys.exit(main())