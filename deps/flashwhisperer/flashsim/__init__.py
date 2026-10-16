"""
flashsim - A simulator for flash-accelerator (wide-flash / line-buffer / prefetch)
timing side channels on microcontroller AES.

Modules
-------
aes     : vectorized AES-128 that emits ordered table-access traces
          for both S-box (1-byte entries) and T-table (4-byte entries) layouts.
flash   : a vectorized flash line-buffer / small-cache timing model.
timing  : turns access traces into per-encryption cycle counts, with an
          optional instruction-fetch contention stream and measurement noise.
attack  : Bernstein-style correlation attack + first-round leakage analysis.
"""

from . import aes, flash, timing, attack  # noqa: F401

__all__ = ["aes", "flash", "timing", "attack"]
__version__ = "0.1.0"
