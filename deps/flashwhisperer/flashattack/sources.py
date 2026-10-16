"""Trace sources: where a Capture comes from. The engine and the attack never care - they
consume a Capture. To add a new hardware interface or data format, implement one
method:

    class MySource:
        def capture(self) -> Capture:
            ...                      # read your interface / file, return a Capture

That is the entire contract (see `TraceSource`). Below are ready-made sources for
recorded files and for the project's serial firmware; a live power/EM/network
interface would look the same.
"""
from __future__ import annotations
from typing import Protocol, runtime_checkable
import numpy as np
from .capture import Capture


@runtime_checkable
class TraceSource(Protocol):
    def capture(self) -> Capture:  # noqa: D401
        """Return a Capture (observed data + timing, no key)."""
        ...


class RecordedSource:
    """Load a Capture from a recorded file (.npz written by Capture.save_npz, or
    a .csv with a 'timing' column and optional plaintext/ciphertext columns)."""
    def __init__(self, path, mode="ecb-enc", keysize=128, **csv_kw):
        self.path, self.mode, self.keysize, self.csv_kw = path, mode, keysize, csv_kw

    def capture(self) -> Capture:
        if str(self.path).endswith(".npz"):
            return Capture.from_npz(self.path)
        return Capture.from_csv(self.path, mode=self.mode, keysize=self.keysize, **self.csv_kw)


class ArraySource:
    """Wrap in-memory arrays (e.g. produced by another agent's capture loop)."""
    def __init__(self, timing, mode="ecb-enc", keysize=128, plaintext=None,
                 ciphertext=None, iv=None, line_shift_last=4, line_shift_prev=2, label=""):
        self._cap = Capture(timing=timing, mode=mode, keysize=keysize, plaintext=plaintext,
                            ciphertext=ciphertext, iv=iv, line_shift_last=line_shift_last,
                            line_shift_prev=line_shift_prev, label=label)

    def capture(self) -> Capture:
        return self._cap


class SerialModesSource:
    """The project's fw_f4_modes / fw_f4_lib firmware over serial. This is a
    *known-key* lab oracle: the device streams timings for host-generated
    plaintexts, and we synthesise the observed ciphertext from `key` (a real
    interface would instead read the ciphertext off the wire). Produces a Capture
    with no key stored.
    """
    def __init__(self, port, mode, key_hex, n, *, acr="00000705", seed="5eed01",
                 impl="ttable", batch_cmd=None):
        self.port, self.mode, self.key = port, mode, bytes.fromhex(key_hex)
        self.n, self.acr, self.seed, self.impl, self.batch_cmd = n, acr, int(seed, 16), impl, batch_cmd

    def capture(self) -> Capture:
        from . import transport, modes, aesref
        tgt = transport.SerialTarget(self.port)
        banner = tgt.banner(); tgt.set_acr(self.acr); tgt.setkey(self.key.hex())
        bc = self.batch_cmd or (("X" if (self.mode == "ecb-enc" and "-lib" in banner)
                                 else "X " + modes.MODE_CHAR[self.mode]))
        material, cyc = transport.collect_oncore(tgt, bc, self.seed, self.n); tgt.close()
        # synthesise observed data (a real wire interface would supply these directly)
        iv = bytes.fromhex("00112233445566778899aabbccddeeff")
        pt = ct = None; ivb = None
        if self.mode == "ecb-enc":
            pt, ct = material, aesref.encrypt_blocks(self.key, material)
        elif self.mode == "cbc-enc":
            ivb = iv; ct = aesref.encrypt_blocks(self.key, material ^ np.frombuffer(iv, np.uint8))
        elif self.mode == "ctr":
            pt = np.zeros_like(material); ct = aesref.encrypt_blocks(self.key, material)
        elif self.mode == "ecb-dec":
            pt, ct = aesref.decrypt_blocks(self.key, material), material
        elif self.mode == "cbc-dec":
            ivb = iv; pt = aesref.decrypt_blocks(self.key, material) ^ np.frombuffer(iv, np.uint8)
        return Capture(timing=cyc, mode=self.mode, keysize=len(self.key) * 8,
                       plaintext=pt, ciphertext=ct, iv=ivb,
                       line_shift_last=4, line_shift_prev=(2 if "ttable" in self.impl else 4),
                       label=self.impl)


# ---------------------------------------------------------------------------
# Protocol oracles: OSCORE (AES-CCM) and SSH (AES-CTR) over IP.
# Both reduce to the CTR path (keystream = P^C); see protocols.py.
# ---------------------------------------------------------------------------

class SimulatedProtocolSource:
    """Hardware-free, flashsim-backed demo of the OSCORE / SSH oracle.

    Generates faithful per-block timing with the project's flash-line-latch model
    (the same collision the F429 shows), optionally amplified K times in-device and
    min-filtered over R network repeats, plus Gaussian network jitter. Produces a
    'ctr'-mode Capture, so the standard engine recovers k10 -> master.

    proto : 'oscore' (AES-CCM counter blocks) or 'ssh' (AES-CTR counter blocks).
    """
    def __init__(self, proto, key_hex, n, *, sigma=0.0, K=1, R=1, seed=0,
                 known_plaintext=True, preset="latch"):
        self.proto = proto
        self.key = bytes.fromhex(key_hex)
        self.n, self.sigma, self.K, self.R, self.seed = n, float(sigma), int(K), int(R), seed
        self.known_plaintext, self.preset = known_plaintext, preset

    def _counters(self, rng):
        from . import protocols
        if self.proto == "oscore":
            # one CCM security context: fixed 13-byte nonce base, climbing Partial IV.
            nonce = bytes(rng.integers(0, 256, 13, dtype=np.uint8))
            return protocols.ccm_counter_blocks(nonce, self.n, L=2, start=1)
        if self.proto == "ssh":
            iv = bytes(rng.integers(0, 256, 16, dtype=np.uint8))
            return protocols.ssh_ctr_blocks(iv, self.n)
        raise ValueError(f"unknown proto {self.proto!r}")

    def capture(self) -> Capture:
        from flashsim.timing import encrypt_and_time
        from flashsim.flash import PRESETS
        from . import aesref, protocols
        rng = np.random.default_rng(self.seed)
        counters = self._counters(rng)
        rk = aesref.key_expansion(self.key)
        # deterministic per-block AES time carrying the last-round line collision
        aes_cyc, _ = encrypt_and_time(counters, rk, "sbox", PRESETS[self.preset], noise_sigma=0.0)
        # in-device amplification (K encryptions of the same block) scales the
        # signal but NOT the fixed network jitter - exactly the boot_attack trick.
        signal = self.K * aes_cyc.astype(float)
        if self.sigma > 0:
            reps = rng.normal(0.0, self.sigma, (self.R, self.n))
            measured = (signal[None, :] + reps).min(axis=0)   # min-filter over R RTTs
        else:
            measured = signal
        keystream = aesref.encrypt_blocks(self.key, counters).astype(np.uint8)
        if self.known_plaintext:
            pt = np.frombuffer(b"CoAP/2.05 Content" .ljust(16, b" ")[:16] if self.proto == "oscore"
                               else b"SSH-2.0-payload!" , np.uint8)[None, :].repeat(self.n, 0)
        else:
            pt = np.zeros((self.n, 16), np.uint8)
        ct = pt ^ keystream
        return protocols.capture_from_observed(pt, ct, measured, label=f"{self.proto}-sim")


class OscoreNetworkSource:
    """Live OSCORE oracle over UDP (CoAP). Sends N requests to the target's OSCORE
    resource, times send->response per request on the host clock (or a PTP/second-
    MCU timestamp fed in via `timing_fn`), and reads the protected response so the
    known plaintext gives keystream = P^C. `decode_fn(resp_bytes) -> (pt16, ct16)`
    extracts the first protected block and its known plaintext for one packet.

    This is the thin glue only; the CoAP/OSCORE framing lives in the attacker
    tool that talks to the firmware (demo/oscore/fw). Supplied so the wire
    format can be swapped without touching the engine.
    """
    def __init__(self, host, port, n, decode_fn, request_fn, *, K=1, R=1,
                 timing_fn=None, timing_from_resp=None):
        self.host, self.port, self.n = host, int(port), int(n)
        self.decode_fn, self.request_fn = decode_fn, request_fn
        self.K, self.R, self.timing_fn, self.timing_from_resp = int(K), int(R), timing_fn, timing_from_resp

    def capture(self) -> Capture:
        from .transport import UdpTarget, collect_udp_latency
        from . import protocols
        tgt = UdpTarget(self.host, self.port)
        pt, ct, tim = collect_udp_latency(tgt, self.n, self.request_fn, self.decode_fn,
                                          K=self.K, R=self.R, timing_fn=self.timing_fn,
                                          timing_from_resp=self.timing_from_resp)
        tgt.close()
        return protocols.capture_from_observed(pt, ct, tim, label="oscore-net")


class SshNetworkSource:
    """Live SSH oracle over TCP: same shape as OscoreNetworkSource but a stream
    transport. `request_fn` drives one timeable packet exchange; `decode_fn`
    returns (pt16, ct16) for the first CTR block of the response."""
    def __init__(self, host, port, n, decode_fn, request_fn, *, K=1, R=1,
                 timing_fn=None, timing_from_resp=None):
        self.host, self.port, self.n = host, int(port), int(n)
        self.decode_fn, self.request_fn = decode_fn, request_fn
        self.K, self.R, self.timing_fn, self.timing_from_resp = int(K), int(R), timing_fn, timing_from_resp

    def capture(self) -> Capture:
        from .transport import TcpTarget, collect_tcp_latency
        from . import protocols
        tgt = TcpTarget(self.host, self.port)
        pt, ct, tim = collect_tcp_latency(tgt, self.n, self.request_fn, self.decode_fn,
                                          K=self.K, R=self.R, timing_fn=self.timing_fn,
                                          timing_from_resp=self.timing_from_resp)
        tgt.close()
        return protocols.capture_from_observed(pt, ct, tim, label="ssh-net")
