"""Reads candidate session keys out of the running game, for sniffer-tool.

The session key is a 4096-byte array in the game's managed heap. This scans the process's
read/write memory for IL2CPP byte arrays of that length that look random, and writes each one
to `<out>/session_<n>.bin`. sniffer-tool picks the right one by checking it against the packets
(`--session-key`, `keys/*.bin`, or the `key` console command).

Read-only: it uses only OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION),
VirtualQueryEx and ReadProcessMemory. Nothing is written to or executed in the game.
The game runs elevated, so this has to be run as administrator too.

Usage: python keyscan.py [pid | process name] [--out keys]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import math
import os
import subprocess
from collections import Counter

PROCESS_NAMES = ("YuanShen.exe", "GenshinImpact.exe")
KEY_SIZE = 4096
# IL2CPP array header on x64: klass, monitor, bounds, max_length; the bytes follow.
MARKER = b"\x00" * 8 + KEY_SIZE.to_bytes(8, "little")
MIN_ENTROPY = 7.5
MAX_KEYS = 256


class MemoryBasicInformation(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD), ("PartitionId", wt.WORD), ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MemoryBasicInformation), ctypes.c_size_t]
kernel32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]


def find_pid(target):
    if target and target.isdigit():
        return int(target)
    names = (target,) if target else PROCESS_NAMES
    listing = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True).stdout
    for line in listing.splitlines():
        fields = [field.strip('"') for field in line.split('","')]
        if fields and fields[0].lower() in (name.lower() for name in names):
            return int(fields[1])
    raise SystemExit("The game is not running.")


def entropy(data):
    return -sum(n / len(data) * math.log2(n / len(data)) for n in Counter(data).values())


def regions(handle):
    """Committed read/write regions."""
    address, info = 0, MemoryBasicInformation()
    while kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info)):
        base, size = info.BaseAddress or 0, info.RegionSize
        address = base + size
        if info.State == 0x1000 and info.Protect in (0x04, 0x40):  # MEM_COMMIT; PAGE_READWRITE / EXECUTE_READWRITE
            yield base, size


def read(handle, address, size):
    buffer, read_size = ctypes.create_string_buffer(size), ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(read_size)):
        return b""
    return buffer.raw[:read_size.value]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", nargs="?", help="process id or name (default: the game)")
    parser.add_argument("--out", default="keys", help="directory for the candidates (default: keys)")
    args = parser.parse_args()

    pid = find_pid(args.target)
    handle = kernel32.OpenProcess(0x0410, False, pid)
    if not handle:
        raise SystemExit(f"Cannot read process {pid} (error {ctypes.get_last_error()}); run as administrator.")

    keys = {}
    for base, size in regions(handle):
        for offset in range(0, size, 64 << 20):
            # Overlap the chunks so an array on a boundary is not missed.
            data = read(handle, base + offset, min((64 << 20) + KEY_SIZE + len(MARKER), size - offset))
            index = data.find(MARKER)
            while index != -1:
                key = data[index + len(MARKER):index + len(MARKER) + KEY_SIZE]
                if len(key) == KEY_SIZE and key not in keys and len(set(key)) > 200 and entropy(key) >= MIN_ENTROPY:
                    keys[key] = base + offset + index + len(MARKER)
                index = data.find(MARKER, index + 1)
    kernel32.CloseHandle(handle)

    os.makedirs(args.out, exist_ok=True)
    for old in os.listdir(args.out):
        if old.startswith("session_") and old.endswith(".bin"):
            os.remove(os.path.join(args.out, old))
    for number, key in enumerate(list(keys)[:MAX_KEYS]):
        with open(os.path.join(args.out, f"session_{number}.bin"), "wb") as file:
            file.write(key)
    print(f"Wrote {min(len(keys), MAX_KEYS)} candidate session key(s) to '{args.out}'.")


if __name__ == "__main__":
    main()
