"""flashleak - is this black-box target leaking through its flash timing?

Built for someone who knows only that bytes go in or out of something doing
crypto: not the mode, not whether they are watching plaintext or ciphertext, not
whether it encrypts or decrypts. Every question is settled by a test whose
outcome differs between the answers.

Two ways in.

**Observation only** - you have blocks and times, no control:

    from flashleak import assess, render
    print(render(assess(blocks, timing)))

**Controlled input** - you can send data and time the response:

    from flashleak import fixed_vs_random, determinism, collect, assess, render
    print(determinism(tgt))            # is averaging worth anything?
    print(fixed_vs_random(tgt))        # model-free: is it leaking at all?
    blocks, t = collect(tgt, 50_000, repeats=3)
    print(render(assess(blocks, t)))

Start with `fixed_vs_random`. It assumes nothing about the cipher and is the most
sensitive thing here; the modelled tests then say whether what it found is the
collision channel, which side of the cipher you are on, and what a key would
cost.

One thing worth knowing before you trust a negative: a flat *model-free* result
does not clear a target. Cache-collision leakage lives in pairs of bytes and is
normally invisible to any single-byte test. That is the whole reason the pair
tests exist.
"""
from .placement import row_offset_from_image
from .probe import (TestResult, data_dependence, floor_check, offset_profile,
                    pair_input_test, pair_output_test, timing_summary)
from .hypotheses import Assessment, Finding, assess, combine_cbc, granularity_sweep
from .report import render, to_json
from .target import (SerialTarget, SimulatedTarget, collect, determinism,
                     fixed_vs_random)

__all__ = [
    "assess", "render", "to_json", "Assessment", "Finding",
    "timing_summary", "data_dependence", "pair_input_test", "pair_output_test",
    "floor_check", "offset_profile", "granularity_sweep", "combine_cbc",
    "TestResult",
    "SimulatedTarget", "SerialTarget", "collect", "determinism",
    "fixed_vs_random",
    # The image half of the table's row geometry; the arithmetic half is
    # flashattack.geometry, and flashattack must not import this package.
    "row_offset_from_image",
]
