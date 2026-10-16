"""Map an AES mode to the block-cipher output the attacker can reconstruct, and
the attack direction. Given the per-trace `material` (16 bytes the firmware used
as plaintext / ciphertext / counter) and the known key, return the (N,16) block
the engine scans plus 'enc'/'dec'.

See EXPOSURE.md for which real usages expose each of these.
"""
from __future__ import annotations
import numpy as np
from . import aesref

# fixed, host-known CBC IV used by the mode firmware (fw_f4_modes/main.c)
DEFAULT_IV = bytes.fromhex("00112233445566778899aabbccddeeff")


def known_output(mode, material, key, iv=DEFAULT_IV):
    """Return (known_blocks (N,16) int, direction). `material` is (N,16) uint8."""
    m = np.asarray(material, np.uint8)
    ivv = np.frombuffer(iv, np.uint8)[None, :]
    if mode in ("ecb-enc", "ecb"):
        return aesref.encrypt_blocks(key, m).astype(int), "enc"
    if mode == "cbc-enc":
        return aesref.encrypt_blocks(key, m ^ ivv).astype(int), "enc"
    if mode == "ctr":
        # keystream block = E(k, counter); firmware uses `material` as the counter
        return aesref.encrypt_blocks(key, m).astype(int), "enc"
    if mode == "gcm":
        # 96-bit IV in material[:12]; data-block counter = IV || 0x00000002
        ctr = m.copy()
        ctr[:, 12:] = np.array([0, 0, 0, 2], np.uint8)
        return aesref.encrypt_blocks(key, ctr).astype(int), "enc"
    if mode in ("ecb-dec", "cbc-dec", "dec"):
        # AES-decrypt output = InvCipher(ciphertext); for CBC the mode XORs IV
        # afterwards but the block-cipher output (what the S-box leak is about) is
        # the InvCipher result, independent of the IV.
        return aesref.decrypt_blocks(key, m).astype(int), "dec"
    raise ValueError(f"unknown mode {mode!r}")


# firmware command character for fw_f4_modes' `X <mode> ...`
MODE_CHAR = {"ecb-enc": "e", "ecb": "e", "ecb-dec": "d", "cbc-enc": "c",
             "cbc-dec": "b", "ctr": "t"}

ALL_MODES = ["ecb-enc", "ecb-dec", "cbc-enc", "cbc-dec", "ctr", "gcm"]
