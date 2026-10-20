"""Place RIOT's AES Te0 table in SRAM in a disposable checkout.

The saved source bytes can be restored with --restore. This is an experimental
control, not a mitigation claim: it changes storage for one table only.
"""

import argparse
from pathlib import Path

SOURCE = Path("sys/crypto/aes.c")
FLASH_DECL = b"static const u32 Te0[256] = {"
RAM_DECL = b'static const u32 Te0[256] __attribute__((section(".data"))) = {'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("riot", type=Path)
    parser.add_argument("--restore", action="store_true")
    args = parser.parse_args()
    path = args.riot / SOURCE
    backup = path.with_suffix(path.suffix + ".ota-backup")
    if args.restore:
        if backup.exists():
            path.write_bytes(backup.read_bytes())
            backup.unlink()
        return
    source = path.read_bytes()
    if backup.exists():
        if RAM_DECL not in source:
            raise SystemExit("backup exists but table is not in SRAM section")
        return
    if source.count(FLASH_DECL) != 1:
        raise SystemExit("RIOT AES source does not match the pinned version")
    backup.write_bytes(source)
    path.write_bytes(source.replace(FLASH_DECL, RAM_DECL))


if __name__ == "__main__":
    main()
