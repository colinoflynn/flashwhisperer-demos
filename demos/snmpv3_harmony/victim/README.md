# The arms, and what is deliberately not in here

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

Harmony 3 is not a clone and is not under `deps/`: MPLAB X's Content Manager
installs it, one versioned component at a time. So there is no vendor tree here
to overlay, and each arm is a script that edits one of Harmony's files in place
and puts it back.

| | |
|---|---|
| `arm_b_cache_off.py` | `Config.K0 = 2`, the data cache off. The textbook control, and half of the build that recovers. The resulting diff is `arm_b_main.c.patch`, readable without the toolchain |
| `arm_e_precon.py` | writes `PRECON` **after** `SYS_Initialize`, for `PFMWS` 7 or 2 or `PREFEN` 1, with the cache left on. This is the flash controller on its own, and it is a null |
| `arm_f_aes_probe.py` | CP0 Count around `wc_AesCfbEncrypt`, ringed and dumped over UART2. The cipher's own clock, and what both shipped vectors are |

Each takes `apply` and `revert`, saves the vendor file before its first edit so
`revert` has something to restore, and preserves the tree's CRLF endings.

```bash
python demos/snmpv3_harmony/victim/arm_b_cache_off.py apply
python demos/snmpv3_harmony/victim/arm_f_aes_probe.py apply
cd <harmony>/net_apps_pic32mz/apps/snmpv3_nvm_mpfs/firmware/pic32mz_ef_sk_freertos.X
make CONF=pic32mz_ef_sk_freertos
```

Arms B and F touch different files, so both together give the cache-off cipher
probe, which is the arm that recovers the key. `PRECON` must be written after
`SYS_Initialize` and not before: an earlier arm set it at the top of `main()`
and `SYS_Initialize` overwrote it on the next line, so that arm ran with the
shipped `PRECON` rather than the one its name claimed.

MPLAB X **v6.20**, not v6.25 or later, which dropped support for this board's
Gen-3 PKOB debugger.

## Not here, on purpose

* Microchip's sources. The campaign kept pristine copies of `main.c`,
  `app.c`, `snmpv3_usm.c`, `configuration.h` and wolfCrypt's `aes.c` beside
  these scripts, because the target checkout could vanish. They are the
  vendor's files and this repository does not redistribute them. Each script
  saves its own backup on the first `apply`, so take one that way rather than
  from here.
* The wire arm's victim file. The over-the-wire recovery ran on a build
  that is cache-off plus an uncached alias read of the S-box, and that arm's
  `main.c` is a modified Microchip source rather than a diff, so it is not
  shipped either. The demo README says what the build was and what it cost.
* Two arms that are not single-variable comparisons. One formed the
  uncached alias and shifted `.rodata` by 24 bytes, which moves the table and
  therefore changes two things at once. The other is the superseded `PRECON`
  arm described above.

## Never run two programmers at once

A second `ipecmd` against the board while one is programming left the part
erased and looked exactly like the new firmware hanging at boot.
