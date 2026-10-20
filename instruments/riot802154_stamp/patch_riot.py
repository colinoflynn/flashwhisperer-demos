"""Install/remove the radio END timing hook in a disposable RIOT checkout.

The hook runs only in OTA_STAMP builds. This script refuses to alter a driver
whose expected source anchors do not match, and preserves its exact bytes.
"""

import argparse
from pathlib import Path

DRIVER = Path("cpu/nrf52/radio/nrf802154/nrf802154_radio.c")
DECL_ANCHOR = b"void isr_radio(void)\n{"
EVENT_ANCHOR = b"    if (NRF_RADIO->EVENTS_END) {\n        NRF_RADIO->EVENTS_END = 0;"
DECL = (b"#ifdef OTA_STAMP\n"
        b"extern void ota_radio_end_stamp(uint32_t packetptr, uint8_t direction, uint8_t crc_ok);\n"
        b"#endif\n\n")
EVENT = (b"    if (NRF_RADIO->EVENTS_END) {\n"
         b"#ifdef OTA_STAMP\n"
         b"        ota_radio_end_stamp(NRF_RADIO->PACKETPTR,\n"
         b"                            _state == STATE_TX ? 1 : (_state == STATE_RX ? 2 : 0),\n"
         b"                            NRF_RADIO->CRCSTATUS);\n"
         b"#endif\n"
         b"        NRF_RADIO->EVENTS_END = 0;")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("riot", type=Path, help="disposable RIOT checkout")
    parser.add_argument("--restore", action="store_true")
    args = parser.parse_args()
    path = args.riot / DRIVER
    backup = path.with_suffix(path.suffix + ".ota-backup")
    if args.restore:
        if backup.exists():
            path.write_bytes(backup.read_bytes())
            backup.unlink()
        return
    original = path.read_bytes()
    if backup.exists():
        if b"ota_radio_end_stamp" not in original:
            raise SystemExit("backup exists but driver is not instrumented")
        return
    newline = b"\r\n" if b"\r\n" in original else b"\n"
    source = original.replace(b"\r\n", b"\n")
    if source.count(DECL_ANCHOR) != 1 or source.count(EVENT_ANCHOR) != 1:
        raise SystemExit("RIOT radio driver does not match the pinned source")
    patched = source.replace(DECL_ANCHOR, DECL + DECL_ANCHOR)
    patched = patched.replace(EVENT_ANCHOR, EVENT)
    if newline == b"\r\n":
        patched = patched.replace(b"\n", b"\r\n")
    backup.write_bytes(original)
    path.write_bytes(patched)


if __name__ == "__main__":
    main()
