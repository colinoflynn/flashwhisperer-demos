# Can a static tool tell whether the AES tables will be in flash?

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

> Status: implemented and scored. `flashleak placement` decides the
> placement question on 38/38 labelled artefacts - from a linked `.elf`
> and from a raw `.bin` with nothing else - with no false negatives in
> either mode, plus 5/5 on a held-out set of firmware other agents built
> during the same session (§5.3). It answers the *build* question, not the
> *exploitability* question, and §5.2 names the five builds where those two
> come apart. On genuinely third-party vendor firmware it mostly answers
> `UNDETERMINED`, and §5.4 says why.
>
> All numbers below were produced by running the tool; the corpus is this
> repo's own firmware, whose leak/no-leak status was established on silicon.

Every break in this repo rests on a placement property. `fwscan` already
answers *"does this image contain AES lookup tables, and of what shape?"*  -  a
property of the library. But ST's X-CUBE-CRYPTOLIB, the same vendor binary,
the same ciphertext, one linker line apart, is either

* a full AES-128 key in 20 000 timings, or
* `sd = 0.00`, a single cycle count, 0/16 - and 20–25 % faster

([`research/exposure/ST_CRYPTOLIB.md`](../../research/exposure/ST_CRYPTOLIB.md) §4). No functional test
can see the difference; the ciphertext is identical. The question here is
whether a *static* tool can.

> Does the tool find this? Yes, and the harder half of the pair too. Given
> only `st_cta.bin` - the fixed build, a raw binary with no symbols - it
> recovers "the tables are at `0x2000_0000`, in SRAM" and returns SAFE, while
> the broken build from the same source returns EXPOSED. §§3.1–3.3 are how.

---

## 1. Three artefacts, three different degrees of certainty

| artefact | what it settles | certainty |
|---|---|---|
| linked `.elf` (+ `.map`) | the run-time address, exactly | exact - it is in the section header |
| raw `.bin` or `.hex` | the run-time address, reconstructed | inferred - four independent signals, §3 |
| `.o` / `.a`, unlinked | *which linker rule is required* | conditional - and the script can be checked |

`flashleak/placement.py` implements all three; `python -m flashleak placement`
is the CLI. The existing `fwscan` / `assess` / `probe` API is untouched.

## 2. Case 1 - the linked ELF. Exact, and the only judgement is the memory map

An ELF section header carries `sh_addr`, the run-time address, even for
`.data`, whose bytes live in flash and whose address is RAM. So:

1. for every `SHF_ALLOC` section with contents, search the section body for the
   AES table fingerprints (reused from `fwscan.patterns()`, one source of truth);
2. the run-time address is `sh_addr + offset_in_section`;
3. classify that address against a part-specific memory map.

Deliberately *not* by symbol name: vendor binaries are stripped, IAR-named, or
carry tables with no symbol at all, and the bytes are the thing that matters.

### 2.1 "Is it `0x08xxxxxx`?" is the wrong rule

It is wrong on exactly the parts that matter. The tool carries a memory map per
family (`--list-parts` prints them) and grades every region into three
levels, because two are not enough:

| level | meaning |
|---|---|
| `EXPOSED` | read through the flash interface - wait states, a 64/128/256-bit row latch, whatever ART sits on top. Present with every cache bit cleared ([`../../research/targets/stm32g474_art_geometry.md`](../../research/targets/stm32g474_art_geometry.md)). |
| `SAFE` | SRAM / CCM / TCM: no wait states, no cache in front. This is the fix. |
| `CACHED_RAM` | RAM that a Cortex-M7 L1 D-cache caches - H7 AXI-SRAM at `0x2400_0000`, F7 SRAM1 at `0x2001_0000`. The flash wait-state channel is gone; a *classical* cache-timing channel is not. This project has not measured it, so it does not get called "safe". |

Three concrete places a naive rule breaks, all reachable on the boards in this rig:

* G4/F3/F4 CCM at `0x1000_0000` - a `0x1xxxxxxx` address that is *safer*
  than SRAM, not more dangerous. A "not 0x08" rule gets this right by accident;
  a "must be 0x20" rule gets it wrong.
* H7: `0x2000_0000` is DTCM, `0x2400_0000` is cached AXI-SRAM. Both are
  "RAM". One is the right answer and one is a different attack.
* F7: the DTCM/SRAM1 boundary moves inside the family. On an F746 the DTCM
  is 64 KB, so `0x2001_0000` is *cacheable SRAM1*; on an F769 the DTCM is
  128 KB and the same address is DTCM. `rigs/fw_f7/link.ld` puts RAM at
  `0x2001_0000` precisely because that is not DTCM on the board here.
  Measured, on one artefact, by changing only `--part`:

  ```
  $ flashleak placement fw_f7_ram_tables.elf --part f746
    [ ~] AES S-box -> 0x20010140  SRAM1
    => VERDICT: CACHED_RAM
  $ flashleak placement fw_f7_ram_tables.elf --part f769
    [ok] AES S-box -> 0x20010140  DTCM (F76x: 128 KB)
    => VERDICT: SAFE
  ```

  Same bytes, same address, opposite verdict. Without a part number, the tool
  returns `UNDETERMINED` for anything in the SRAM region rather than guessing.
* And off the STM32 family entirely, the prefix rule inverts. On an
  nRF52840 the flash is at `0x0000_0000` and the RAM at `0x2000_0000`, so
  "is it `0x08xxxxxx`?" calls a table sitting in flash *safe*. An `nrf_probe`
  build appeared on this bench mid-session (§5.3) and prompted adding the
  profile; its NVMC cache is instruction-side only, so flash *data* reads
  meet the array and its wait states - the F3-shaped case, not measured here.

### 2.2 What the ELF also volunteers

* LMA ≠ VMA. For a writable section the tool reports the load address from
  the program headers next to the run-time address, e.g.
  `.data: LMA 0x080019e0 (flash) -> VMA 0x20000000 (run time)`. This is the
  whole subtlety of the `.bin` case, stated for free.
* NOBITS hedging. If the image has flash tables *and* a zero-initialised RAM
  region big enough to hold them, it says so: the placement may be a run-time
  decision it cannot settle. §6.1.

### 2.3 `EXPOSED` does not tell you which knob to turn - added 2026-09-21

The verdict is a placement fact and the remediation is a per-part fact,
and conflating them sends integrators to the wrong register. So `Part` now
carries a `mitigation` string, printed under an `EXPOSED` verdict as
`what closes it on <part>:`, populated only where this bench measured it
(empty prints nothing - silence rather than a plausible guess).

The CC1352R1F3 is why this exists:

```
  => VERDICT: EXPOSED  - at least one AES table is read from flash at run time.
  what closes it on cc13x2: DO NOT just clear VIMS_CTL.MODE: MODE=OFF leaves the
  16 B line buffer and makes the S-box channel STRONGER (sigma 1.539 -> 4.289,
  full key in 5 000 traces instead of 10 000). What closes it is MODE=OFF *plus*
  VIMS_CTL.IDCODE_LB_DIS=1 - both, and the second is inert on its own.
```

On that part "disable the flash accelerator" - the advice every other page in
this project implies - doubles the attacker's advantage, because with only a
1-entry latch left, adjacency decides everything and adjacency is what the
last-round collision reads ([`../../research/targets/cc1352.md`](../../research/targets/cc1352.md)
§3a, §4). A tool that says `EXPOSED` and stops is complicit in that.

Three parts were added to the map at the same time, all measured on silicon and
all previously missing: `stm32l1` (L152RE, 1 × 8 B latch), `ra2a1`
(code flash at `0x0000_0000` - an `0x08xxxxxx` rule misses it entirely, and
`FCACHEEN = 0` genuinely closes it), and `cc13x2`.

The CC1352 also adds the map's first conditionally existing region. Its
`GPRAM` at `0x1100_0000` is the *same physical 8 KB array as the VIMS cache*,
mapped as RAM only while `VIMS_CTL.MODE = GPRAM`. A table there is plausibly
latch-free - but the region exists only in one VIMS mode, which no static tool
can see, and reads to `0x1100_0000` were not measured here. It is graded
`UNKNOWN`, not `SAFE`, deliberately: this is exactly the `CACHED_RAM` precedent
above, where calling an unmeasured region "safe" would have been a lie.

## 3. Case 2 - raw `.bin` only. The interesting one

This is the realistic case: a vendor download, a dump, a firmware update blob.
Intel HEX counts as this case and is the better version of it: MCU firmware
ships as `.hex` at least as often as `.bin`, and the record stream carries the
real flash base - the one thing the raw-`.bin` path most often lacks (§5.4).
`placement` flattens it and takes the base from the records; on
`rigs/fw_f3_aes` the `.hex` and the `.bin` produce identical addresses.

The trap is that the bytes do not distinguish the two builds. A table
destined for RAM is *still in the flash image* as a `.data` initialiser that the
reset handler copies. `st_flash.bin` and `st_cta.bin` are both 9 188 bytes and
both contain all 2.5 KB of ST's tables. "The table bytes are present" says
nothing.

Four signals, in the order the tool trusts them.

### 3.1 The start-up copy loop → the run-time destination

A `.data` initialiser implies a `(src, dst, len)` triple in the reset handler's
literal pool - `_sidata`, `_sdata`, `_edata`. Their *order* differs by
toolchain, so all orderings inside a small window are tried and filtered on
physical plausibility: `src` in flash and inside the image, `dst`/`end` in RAM,
`len` a multiple of 4, `[src, src+len)` fitting in the image. A table at image
offset `O` inside `[src, src+len)` then has run-time address
`dst + (base + O − src)`.

On `st_cta.bin`, from the image alone:

```
note: start-up copy: 0x080019e0 -> 0x20000000, 2564 bytes (initialiser ends at end of image)
  [ok] AES S-box  -> 0x20000000  SRAM1/2
```

which is exactly what `nm` says of the ELF (`20000000 D AES_sbox`).

> A filter that was not enough, and the false negative it caused.
> The bss-clear loop has the same shape: `_sbss` and `_ebss` are two RAM
> words in the same literal pool, so *any* nearby flash word completes a
> plausible triple. On `rigs/fw_f7` one such phantom - `(0x080013e4,
> 0x20010014, 0xb4)`, built from `_sbss`/`_ebss` and an unrelated literal  - 
> swallowed the S-box at `0x08001434` and turned a flash table into a SAFE
> verdict. A false negative on a build whose key fell on silicon.
>
> The fix is structural rather than statistical. In every GCC/Clang/IAR layout
> in this corpus the image is
> `vectors | text+rodata | init₁ | init₂ | … | init_k <EOF>`: the load regions
> tile the tail of the image contiguously, and the last one ends exactly at
> the end of the image. The tool now accepts only a chain with that property,
> walking backwards from EOF. The bss phantom is anchored nowhere and is
> discarded. (`fw_f7`'s true region is `0x08001534 → 0x20010000, 0x14` bytes,
> and `0x1534 + 0x14 = 0x1548 = 5448` = the file size, to the byte.)

### 3.2 The literal pool → what the code actually reads

Cortex-M code loads a table base from a PC-relative literal, and the literal
holds the run-time address. The tool decodes the two `LDR` literal forms
rather than just scanning for matching words:

```
T1   0100 1ttt iiiiiiii                      LDR  Rt,[PC,#imm8*4]
T2   1111 1000 U101 1111 tttt iiiiiiiiiiii   LDR.W Rt,[PC,#±imm12]
```

with the literal at `align4(pc) + imm`. It also reconstructs `MOVW`/`MOVT`
pairs, for builds (`-mslow-flash-data`, some Clang settings) that materialise an
address with no literal pool entry at all - without that, such a build would
give a false *negative*.

This is the reasoning [`ST_CRYPTOLIB.md`](../../research/exposure/ST_CRYPTOLIB.md) §4 already
used by hand ("`CM3_1T_AES_encrypt`'s literal pool holds only `AES_Te2`, four
times"), mechanised.

> The MOVW/MOVT path is not hypothetical, and neither is what it breaks.
> Built as a test: tiny-AES-c with `-mslow-flash-data`, which suppresses literal
> pools entirely. The tool reports `0 PC-relative literal load(s), 2 MOVW/MOVT
> pair(s)` for the S-box and gets the placement right - but the *first* attempt
> got the addresses wrong by `0x100` on the RAM variant, because
> `find_copy_regions` was scanning only 32-bit words and the start-up
> `(_sidata, _sdata, _edata)` triple is MOVW/MOVT too on such a build. With no
> copy loop found, the group-relocation test was left to break a two-way tie
> between the right delta and one shifted by a table length, and lost it.
> Merging MOVW/MOVT constants into the copy-region scan restores an exact match
> with the ELF. A decoder used in one place and not another is its own bug class.

Measured on the matched pair:

Decoded `LDR Rt,[PC,#n]` loads, per image, of the S-box's and `Te2`'s two
candidate addresses:

| | `0x0800_0100` | `0x2000_0000` | `0x0800_0300` | `0x2000_0200` |
|---|---:|---:|---:|---:|
| `st_flash.bin` (as ST ships) | 5 | 1 | 6 | 0 |
| `st_cta.bin` (ST's fix) | 0 | 6 | 0 | 6 |

The lone `1` in the top row is `_sdata`, the copy loop's destination - not a
reference to a table. §3.3.

### 3.3 The aliasing trap - why one signal is not enough

`_sidata`, the load address of `.data`, is a flash address literal that points
at the first byte of the `.data` initialiser - which, when the tables are what
was moved to RAM, is the first table. On `st_cta.bin`, `_sidata = 0x080019e0`
and `AES_sbox`'s initialiser is at file offset `0x19e0`. A naive "is there a
literal equal to `base + offset`?" therefore fires on the copy loop itself and
calls the fixed build broken.

The tool excludes literals that coincide with a recognised copy-loop source, and
says so in the evidence:

```
- 1 literal load(s) of 0x080019e0 IGNORED: that address is a recognised
  copy-loop source (_sidata), which aliases the first table in .data
- code loads the RAM address 0x20000000: 6 PC-relative literal load(s)
- decision: the copy loop maps it to RAM AND code loads that RAM address
            - two independent signals agreeing
```

And `_sdata` is the mirror image. It is the copy loop's *destination*, so
when the tables are first in `.data` it aliases the table's run-time address
exactly as `_sidata` aliases its load address - and a literal matching it is not
evidence the cipher reads RAM either. It is excluded symmetrically. On
`st_cta.bin` that leaves 5 genuine references to the S-box's RAM address out of
6, and all 6 of `Te2`'s, which is untouched by either alias; on a minimal image
whose only RAM literal *is* `_sdata` it leaves none, and the verdict correctly
falls back to the copy-loop mapping alone.

This is the single reason the two signals are kept separate and cross-checked
rather than OR-ed together. Neither literal that the *start-up code* needs is
allowed to vote on what the *cipher* reads.

### 3.4 Group relocation - recovering a run-time base with no copy loop at all

A section can be given a RAM address with no copy loop covering it. That is
a real and easy mistake - it is the bug in *ST's own published snippet*
(`user_SAFEMEM 0x20030000: { *(CMOX_CTA_PROTECTED_DATA) }` has no load region;
see the comment in [`rigs/fw_g4_st/link_cta.ld`](../../rigs/fw_g4_st/link_cta.ld)).
There is then no `(src, dst, len)` triple to find.

But the linker still resolved every table symbol to the new base, so the
literal pool holds N addresses whose relative spacing matches the tables'
spacing in the image. One shared delta explains all of them at once, and it is
recoverable knowing nothing about the start-up code:

> for every table offset `Oᵢ` and every loaded literal `V`, score the
> hypothesis `δ = V − (base + Oᵢ)` by how many *other* tables have
> `base + Oⱼ + δ` also in the loaded-literal set; take the best-supported `δ`.

Built as a test case: mbedTLS linked with `.rodata` sent to CCM at
`0x1000_0000` via `> CCM AT > FLASH`, with a stock startup that copies only
`.data`. From the raw `.bin`:

```
note: literal pool is consistent with the whole table group being relocated by
      +0x7ffe784: 10 of 10 table addresses appear as loaded literals at that
      offset. Run-time base 0x100000c0.
  [ok] AES S-box -> 0x100000c0  CCM SRAM     ... Td3 -> 0x10001ec0  CCM SRAM
  => VERDICT: SAFE
```

10 of 10, and the recovered base matches the ELF exactly. Without this the
`.bin` verdict was EXPOSED - a false positive on a build that does not read
flash. (The build is also *functionally* broken, because nothing initialises
CCM; the tool flags that the relocation has no copy loop behind it.)

> The shadow-table trap, found by a test rather than by thinking about it.
> `rigs/fw_f4`'s `aes.c` keeps `te0_ram[256] … te3_ram[256]` in `.bss` at
> exactly the same 1 KB spacing as `Te0..Te3` in flash. Those four `.bss`
> addresses therefore fit a "the whole group moved to RAM" hypothesis perfectly,
> with support 4, and the tool duly reported the four T-tables at their shadow
> addresses - while the ELF says they are in flash and the key fell on silicon.
> The test that caught it is the cheapest one in the file: *does the `.bin` path
> produce the same addresses as the `.elf` path on the same build?*
>
> The fix is a veto, and it is the right shape: if any table in the group is
> demonstrably read where it is stored - a literal holding its own flash
> address, which `SBOX` has two instructions away - then the group did not
> move, and any delta that fits the others is a coincidence. A group
> relocation also has to preserve alignment (`δ ≡ 0 mod 4`).
>
> This is worth stating plainly because it is the general hazard of the
> relocation test: a build that keeps *both* copies produces two self-consistent
> stories, and only per-table evidence breaks the tie.
>
> A second, quieter tie comes free with the same geometry: when tables sit end
> to end, `δ` and `δ + table_size` fit equally well - one maps each table to its
> own address, the other to its neighbour's. The tie-break is the tightest
> packing (the lowest highest-mapped address), which is the un-shifted reading.

A free diagnostic falls out of the same arithmetic: a wrong `--base`. If
`base + δ` is itself a plausible flash base on the part, the likelier story is
not that the tables moved but that the base you supplied is wrong - and a wrong
base silently invalidates every address in the report. Told that
`fixed_tinyaes.bin` is XIP at `0x9000_0000` when it is really at `0x0800_0000`:

```
note: literal pool is consistent with the whole table group being relocated by
      -0x88000000 ... Run-time base 0x080011b8.
note: ...but 0x08000000 is itself a plausible flash base on this part. If the
      image is mapped there rather than at 0x90000000, nothing moved and every
      address above is off by -0x88000000. Re-run with --base 0x8000000.
```

Exactly the right base, recovered from the literal pool alone.

### 3.5 The anchor case - when no literal holds the table's address at all

GCC merges adjacent `.rodata` and addresses the whole block from one anchor,
reaching a table with a constant displacement. TinyCrypt's
`tc_aes128_set_encrypt_key` is the clean example: `ldr r4,<.rodata>` followed by
`ldrb r3,[r4,#44]` - the relocation is `R_ARM_ABS32` against the *section*, and
the S-box's own address never appears as a literal.

Requiring an exact literal match therefore returned UNDETERMINED on three
builds whose keys fell on silicon (`fw_f7`, `fw_f7_rsm`, `fw_f7_rsm DTCM=1`).
The tool now also accepts an anchor `V` with `0 < A − V ≤ 4095` - the range of
`LDRB.W Rt,[Rn,#imm12]` - provided `V` is in the *same exposure class* as `A`,
and reports the displacement it used. That recovers all three without changing
any other verdict.

### 3.6 The precedence, and what makes a verdict *confident*

For each table, in order:

1. copy loop maps it to RAM and a literal loads that RAM address → RAM (two
   independent signals);
2. a literal loads the flash load address (and is not an aliased `_sidata`) → flash;
3. copy loop only, no literal → RAM, flagged as unconfirmed;
4. group relocation (vetoed if any table is read in place) → the relocated address;
5. an anchor within `LDRB.W` range in the same exposure class → in place;
6. nothing at all → downgraded to `UNDETERMINED`, not to EXPOSED. "Stays in
   flash" without a copy loop and without a literal is an assumption, not a
   finding, and the tool refuses to dress it up as one.

And one override on top of all six: if the flash base was assumed rather than
read (no vector table at offset 0), any verdict that is not backed by a signal
which would have *failed* under a wrong base is downgraded to `UNDETERMINED`
too. §5.4 is the case that forced that.

Every line of that reasoning is printed as evidence under each table, so a
verdict can be argued with rather than taken on trust. The image-level verdict
is the worst table's: one EXPOSED table makes the image EXPOSED, and an image
whose every table is UNKNOWN is UNDETERMINED, never SAFE.

## 4. Case 3 - `.o` / `.a`, before linking. ST's case

A relocatable object has section names and flags but no addresses. The only
correct verdict is conditional, and a tool's job is to say *which rule* and
then check whether a supplied script contains it.

Run over ST's shipped archive (326 ELF members):

```
$ flashleak placement libSTM32Cryptographic_CM4.a --part g4 \
      --ld rigs/fw_g4_st/link.ld --ld rigs/fw_g4_st/link_cta.ld

  note: 326 ELF member(s) scanned
  note: CMOX_CTA_PROTECTED_DATA: CTA = Cache Timing Attack. ST's wiki tells the
        integrator to map this section into non-cacheable RAM.
  note: required rule (GNU ld): put *(CMOX_CTA_PROTECTED_DATA) inside an output
        section whose VMA is RAM and whose LMA is flash (`> RAM AT > FLASH`), so
        the start-up copy actually initialises it.
  [ ?] AES S-box / AES inverse S-box / Te2 (BE) / Td2 (BE)
           -> (unlinked)  section CMOX_CTA_PROTECTED_DATA  lookup_tables.obj
  => VERDICT: CONDITIONAL

  ld rigs/fw_g4_st/link.ld:     does NOT mention CMOX_CTA_PROTECTED_DATA
                                    - falls through to the read-only region
                                    next to .text, i.e. FLASH
  ld rigs/fw_g4_st/link_cta.ld: PLACES it in output section .data
                                    -> region RAM AT > FLASH
```

The heuristic that makes this generalise past ST: a table in a section whose
name is not `.rodata`/`.data`/`.text` is a library that expects to be placed,
and the tool says so even for a section name it has never heard of.

### 4.1 The linker-script check, run over ST's whole package

Scanning `.ld` / `.icf` / `.sct` is easy and exact, and it is the check that
would have caught the original finding:

```
linker scripts found: 2277   ({'.icf': 1101, '.ld': 741, '.sct': 435})
scripts that place CMOX_CTA_PROTECTED_DATA: 0
scripts that mention it only inside a comment: 0
```

Independently reproducing `ST_CRYPTOLIB.md`'s 2 277 / 0 with a different
implementation, and adding the dialect split. Three details that matter for
getting this right:

* comments are stripped first. A commented-out rule places nothing. ST's own
  worked example appears inside a comment in more than one file in the wild.
* mentioning the section is not enough. The tool reports the *output
  section* and the *region*, by brace matching, and warns when a section is
  placed in RAM with no `AT >` load region - which is exactly ST's published
  STM32CubeIDE snippet, and which leaves the tables uninitialised.
* three dialects: GNU `*(NAME)`, IAR `place in R { section NAME }`, Arm scatter.

## 5. Scoring, over a corpus whose labels came off real silicon

This project has something most static-analysis work does not: 38 artefacts, most of them
with behaviour measured on hardware, including two matched pairs that
differ *only* in placement.

Two questions are scored separately, on purpose, because conflating them is how
a tool like this gets oversold.

The labels and the scoring live in
[`research/placement_corpus.py`](../../research/placement_corpus.py), so the tables
below can be regenerated rather than taken on trust:

```bash
python research/placement_corpus.py --build /tmp/corpus   # what to build, and what is missing
python research/placement_corpus.py --root  /tmp/corpus   # score it
```

### 5.1 (a) Placement - will the tables be read from flash?

Ground truth: the linked ELF's section headers. The `.bin` path is scored
against that, i.e. against exact truth it does not get to see.

| | TP | FP | TN | FN | total |
|---|---:|---:|---:|---:|---:|
| linked `.elf` | 25 | 0 | 13 | 0 | 38 |
| raw `.bin` only | 25 | 0 | 13 | 0 | 38 |

Every non-EXPOSED verdict also matched in *kind* (SAFE vs CACHED_RAM vs
NO-TABLES), not merely in polarity. The `.bin` path reproduces the ELF verdict
on all 38, including the artefacts where the tables are *not* in flash and
the bytes are nevertheless present in the image.

The corpus:

| build | part | truth | ELF | BIN | hardware |
|---|---|---|---|---|---|
| mbedTLS default (4 T-tables) | F4 | flash | EXPOSED | EXPOSED | key recovered |
| mbedTLS `FEWER_TABLES` | F4 | flash | EXPOSED | EXPOSED | key recovered |
| wolfSSL default | F4 | flash | EXPOSED | EXPOSED | key recovered |
| wolfSSL `SMALL_TABLES` | F4 | flash | EXPOSED | EXPOSED | key recovered |
| OpenSSL default | F4 | flash | EXPOSED | EXPOSED | key recovered |
| Nettle | F4 | flash | EXPOSED | EXPOSED | key recovered |
| GmSSL | F4 | flash | EXPOSED | EXPOSED | key recovered |
| tiny-AES-c | F4 | flash | EXPOSED | EXPOSED | key recovered |
| TinyCrypt | F4 | flash | EXPOSED | EXPOSED | key recovered |
| LoRaMac-node soft-se | F4 | flash | EXPOSED | EXPOSED | key recovered |
| OpenSSL `OPENSSL_AES_CONST_TIME` | F4 | none | NO-TABLES | NO-TABLES | measured null |
| BearSSL `aes_ct` | F4 | none | NO-TABLES | NO-TABLES | measured null |
| ST cryptolib, `link.ld` (as shipped) | G4 | flash | EXPOSED | EXPOSED | key recovered |
| ST cryptolib, `link_cta.ld` (ST's fix) | G4 | ram | SAFE | SAFE | measured null |
| fw_f4 (own AES) | F4 | flash | EXPOSED | EXPOSED | key recovered |
| fw_f4 + `.rodata`→RAM | F4 | ram | SAFE | SAFE |  -  |
| fw_f4_ctguard (RAM chosen at run time) | F4 | flash | EXPOSED | EXPOSED | measured null |
| fw_g4 (own AES) | G4 | flash | EXPOSED | EXPOSED | key recovered |
| fw_f3_aes | F3 | flash | EXPOSED | EXPOSED | measured null |
| fw_f4_modes | F4 | flash | EXPOSED | EXPOSED | key recovered |
| fw_f4_boot | F4 | flash | EXPOSED | EXPOSED | key recovered |
| fw_f4_rsm (rotating masked S-box) | F4 | flash | EXPOSED | EXPOSED | measured null |
| fw_f4_masked | F4 | flash | EXPOSED | EXPOSED | measured null |
| fw_f3_scode | F3 | flash | EXPOSED | EXPOSED |  -  |
| fw_f7 | F7 | flash | EXPOSED | EXPOSED | key recovered |
| fw_f7 + `.rodata`→SRAM1 | F7 | cached-ram | CACHED_RAM | CACHED_RAM |  -  |
| fw_f7_rsm | F7 | flash | EXPOSED | EXPOSED | key recovered |
| fw_f7_rsm `DTCM=1` (copied at run time) | F7 | flash | EXPOSED | EXPOSED | measured null |
| sboot `ROM_SBOX=0` (S-box built in RAM) | G4 | none | NO-TABLES | NO-TABLES | measured null |
| sboot `ROM_SBOX=1` (S-box in flash) | G4 | flash | EXPOSED | EXPOSED | key recovered |
| mbedTLS, `.rodata`→RAM | F4 | ram | SAFE | SAFE |  -  |
| tiny-AES-c, `.rodata`→RAM | F4 | ram | SAFE | SAFE |  -  |
| Nettle, `.rodata`→RAM | F4 | ram | SAFE | SAFE |  -  |
| wolfSSL, `.rodata`→RAM | F4 | ram | SAFE | SAFE |  -  |
| OpenSSL, `.rodata`→RAM | F4 | ram | SAFE | SAFE |  -  |
| mbedTLS, `.rodata`→CCM, no copy loop | F4 | ram | SAFE | SAFE |  -  |
| tiny-AES-c, `-mslow-flash-data` (no literal pool) | F4 | flash | EXPOSED | EXPOSED |  -  |
| tiny-AES-c, `-mslow-flash-data` + `.rodata`→RAM | F4 | ram | SAFE | SAFE |  -  |

Thirteen of the thirty-eight are negatives, and they are not all the same kind of
negative - two constant-time cores, one run-time-generated table, seven
linker-moved (one of them with no literal pool at all), one
relocated-without-a-copy-loop, one cached RAM, one CCM. That matters: a tool
that only ever sees flash tables can score 25/25 by saying EXPOSED to
everything, and the negatives are where the method is actually tested.

### 5.2 (b) Exploitability - does EXPOSED mean a key fell?

A different question, and the honest answer is that they are not the same set.
Over the 27 artefacts with a hardware label, scoring `EXPOSED` against *"a full
key was recovered on silicon"*:

| TP | FP | TN | FN |
|---:|---:|---:|---:|
| 18 | 5 | 4 | 0 |

Zero false negatives. Every build whose key fell is called EXPOSED, by both
the ELF path and the raw-`.bin` path. That is the property that matters for a
triage tool, and it is the one this repo would call a failed tool for missing.

The five false positives are the finding, not an embarrassment, and they are
five *different* reasons placement is necessary but not sufficient:

| build | why EXPOSED is not a key |
|---|---|
| `fw_f3_aes` | The part. F303 has wait states but the data path measured *bit-exactly constant time* ([`research/mechanism/WHAT_LEAKS_ON_F3.md`](../../research/mechanism/WHAT_LEAKS_ON_F3.md)). Tables in flash, no data channel. |
| `fw_f4_ctguard` | Run-time placement. `aes.c` carries both copies behind one pointer; the shipping path reads `.bss`, the flash tables are the *positive control*. §6.1. |
| `fw_f7_rsm DTCM=1` | Run-time relocation. 4.75 KB `memcpy`'d to DTCM at boot; `t = 0.00`. |
| `fw_f4_rsm` | A countermeasure in the cipher. Rotating masked S-box: 0/16 - while the *plain control in the same image* reads 16/16. |
| `fw_f4_masked` | Same shape: masked tables, control leaks. |

So the tool's verdict is "the tables are read from flash", and that is all it
claims. Two of the five (`fw_f4_ctguard`, `fw_f7_rsm DTCM=1`) are hedged
automatically - see §6.1. Two (`fw_f4_rsm`, `fw_f4_masked`) are masking, which
is a cipher property outside this tool's remit. One (`fw_f3_aes`) is a property
of the silicon and needs [`DATASHEETS.md`](../../research/reference/DATASHEETS.md), not the binary.

### 5.3 Held out: firmware built by other agents during the same session

Five firmware trees appeared under `rigs/fw_*` after the tool was written
and frozen, built by the agents driving the boards. They had no knowledge of
this module and it had none of them, which makes them a clean held-out set.

| build | part | ELF | BIN | agree |
|---|---|---|---|---|
| `fw_h7` (H723 AES victim) | H7 | EXPOSED | EXPOSED | yes |
| `fw_g4_ctguard` (G474 ctguard port) | G4 | EXPOSED | EXPOSED | yes |
| `fw_h7_cache` (cache geometry probe) | H7 | NO-TABLES | NO-TABLES | yes |
| `fw_l5_cache` (L552 cache probe) | L5 | NO-TABLES | NO-TABLES | yes |
| `fw_nrf_probe` (nRF52840 flash probe) |  -  | NO-TABLES | NO-TABLES | yes |

5/5, and two of them are worth more than the tally:

* `fw_h7` independently validates the `CACHED_RAM` level. Its `link.ld`  - 
  written for a different purpose entirely - declares
  `DTCM 0x20000000 LENGTH 128K` and `AXI 0x24000000 LENGTH 320K`, exactly the
  H7 geometry §2.1 claims, and puts the tables in flash with two RAM copies:
  `.bss` in DTCM and `.axibss` in cached AXI-SRAM. The tool reports EXPOSED and
  names both hedges without being told anything:

  ```
  note: flash-resident tables coexist with zero-initialised RAM buffers
        (.bss (4544 B @ 0x20000040), .axibss (4352 B @ 0x24000000)). ...
        the run-time placement is a RUNTIME decision this analysis cannot settle.
  ```

  A three-way run-time-selected placement (flash / DTCM / cached AXI-SRAM) is
  precisely the case where the static answer must be "EXPOSED, and here is why
  you should not trust that on its own".
* `fw_nrf_probe` is an nRF52840, where flash is at `0x0000_0000`. A tool
  whose rule is "is the address `0x08xxxxxx`?" would call a table sitting in
  that flash safe. This one has no AES tables so nothing turns on it here,
  but it prompted adding `nrf52` / `nrf53` profiles: flash at 0, RAM at
  `0x2000_0000`, and the note that the NVMC cache on an nRF52 is
  *instruction-side only*, so data reads hit the array with wait states - the
  F3-shaped case. ~~Not measured on this bench; the region map is from the
  datasheet and the exposure from the mechanism.~~ Superseded: the nRF52840
  has since been measured - the instruction-side-only claim was confirmed
  directly with the part's own `IHIT`/`IMISS` counters, and a 1-entry 16-byte
  read latch that no register reaches was found behind it, from which the full
  key falls in 6 250 traces ([`../../research/targets/nrf52840.md`](../../research/targets/nrf52840.md)).

A sixth build, and it is only half held out. `fw_cc1352_aes` (TI
CC1352R1F3) was added 2026-09-21. The tool's table-finding and address
resolution had no knowledge of it and got it right first time - `EXPOSED`, with
the S-box at `0x0000_6200`, the same address the firmware itself reports over
its UART (`sbox=0x00006200`), which is about as direct a cross-check of the
ELF path as this corpus offers. It also volunteered the right hedge, because
that build really does switch tables at run time (`aes_use_ram()`):

```
note: flash-resident tables coexist with zero-initialised RAM buffers
      (.bss (21012 B @ 0x200000d8)). ... the run-time placement is a RUNTIME
      decision this analysis cannot settle.
```

But the `cc13x2` memory map was written by the same agent as the firmware,
so this is a held-out test of the *placement logic* and not of the region
map. Counting it as 6/6 would be counting it twice; it is listed here as a
confirmation of the ELF path and nothing stronger.

### 5.4 Held out: real third-party vendor firmware, and it mostly says "don't know"

Everything in §5.1 is firmware this project built. The one genuinely
third-party corpus to hand is the ST-LINK/V2 and V2-1 application images
(8 images from `STLinkUpgrade.jar`, AES-decrypted and RLE-unpacked by the
triage in [`PRODUCT_TARGETS.md`](../../research/exposure/PRODUCT_TARGETS.md) §1), where `fwscan` found
a complete 256-byte S-box in 7 of the 8 - a confirmed software table AES in a
shipping product. Running `placement` on them:

| verdict | images |
|---|---|
| `UNDETERMINED` | 7 |
| `NO-TABLES` | 1 (`f2_1.bin`, the one `fwscan` also finds nothing in) |
| `EXPOSED` / `SAFE` | 0 |

That is the right answer, and it is a poor one. Three things go wrong at
once, and they are the honest limits of the raw-`.bin` method:

1. No vector table at offset 0, so the flash base is a guess. These are
   application images that live at an offset, behind the 16 KB bootloader ST
   does not distribute. Every address computed from a guessed base is a guess.
2. The image has been RLE-unpacked, so byte offsets are reconstructed rather
   than read - and the S-box lands at *odd* offsets (`0xacfe`, `0x7eee`,
   `0xcf9f`), which a linker would not produce. The unpacked stream is not a
   faithful flash map.
3. One table, so the group methods have no leverage. §3.4 works by finding a
   delta that explains *several* tables at once. With a single S-box, "support
   ≥ 2" is unreachable, and a single coincidental literal is worth nothing. The
   base-recovery variant of the same trick returns a best candidate with support
   1 on three images and nothing on the rest - i.e. noise.

> One build initially answered `SAFE`, and it was wrong. `f1_1.bin` has a
> copy region that happens to cover the S-box's offset, so the tool mapped it
> into SRAM and reported SAFE - on an image whose base it had assumed. A wrong
> base makes every such mapping arithmetic on an assumption. The tool now
> refuses a `SAFE` or `EXPOSED` verdict whenever the base was guessed *and*
> nothing corroborates it - corroboration being a signal that would have
> failed under a wrong base: a literal that matches, or a copy region that
> tiles the tail of the image exactly. That one change turns a confident wrong
> answer into `UNDETERMINED`, which is the finding this section exists to
> report.

The practical reading: the method is strong on an image a linker produced and
weak on a vendor blob that has been re-packed and re-based. For those, the
answer is `--base` from a datasheet or a dump, or a run-time measurement.

## 6. Where static analysis *necessarily* fails

The five things this project measures, and whether a static tool can see them:

| measured quantity | can a static tool see it? |
|---|---|
| where the tables live | yes - that is this whole document |
| `FLASH_ACR` at the moment of the cipher | no |
| MPU / cacheability attributes at run time | no |
| whether a bootloader relocated the image | no |
| whether the table read is *data-dependent* at all (masking, bitslicing) | partly - "no tables" is visible, a countermeasure applied to tables is not |

### 6.1 Run-time placement: the failure with a hedge

The most instructive case in the corpus, and it starts with a correction. It is
natural to reach for `fw_f4` vs `fw_f4_ctguard` as "the matched pair that
differs only in placement" - [`rigs/fw_f4_ctguard/README.md`](../../rigs/fw_f4_ctguard/README.md)
tabulates *RAM* against *flash* for the same cipher. But they are not two builds:
`diff rigs/fw_f4/aes.c rigs/fw_f4_ctguard/aes.c` is empty, and both
images carry the tables in `.rodata` *and* a `.bss` copy, with

```c
void aes_use_ram(int on) {
    if (on) { SB = sbox_ram; T0 = te0_ram; ... }
    else    { SB = SBOX;     T0 = Te0;     ... }
}
```

flips between them at run time. Which memory the cipher reads is decided by a
function call, and no static tool can decide it. Both builds must be called
EXPOSED, and both calls are correct about the stored copy and wrong about the
shipping path.

The tool does not stay quiet about it. When the tables are EXPOSED *and* the
image owns enough zero-filled RAM to hold them, it says so - from the ELF via
NOBITS section sizes, and from the raw `.bin` by recovering the `(_sbss, _ebss)`
pair the same way as the copy triple:

```
note: zero-filled RAM of at least 4872 bytes (0x20000000+4872) - enough to hold
      the 4352 bytes of tables found. If this build copies them there at start-up
      and reads them through a pointer, the run-time placement is a RUNTIME
      decision and the EXPOSED verdict above is about the stored copy.
```

> A detector that fires on everything says nothing. The first version of
> this check "found" a 4 MB zero region at `0x70180e08` in every image - that
> address is AES table data read as a little-endian word. Constraining it to
> the first 4 KB of the image and to values that are *actually loaded* by a
> decoded `LDR` literal makes it discriminate: it fires on `fw_f4`,
> `fw_f4_ctguard` and `fw_f7_rsm` and stays silent on `tiny-AES-c`, `fw_g4_st`
> and the rest.

This is the argument for the run-time detector in the sibling workstream.
[`rigs/fw_f4_ctguard/`](../../rigs/fw_f4_ctguard) times the cipher at boot
and aborts if the time depends on the input - spread 0 cycles with the
tables in RAM against 177 with them in flash, on the real device, at the
real `FLASH_ACR`, after whatever the bootloader and the RTOS did. The static
tool cannot get there, and the run-time detector cannot scale to a vendor
archive you have not flashed. They answer different halves.

The two write-ups agree on the division: `ctguard`'s own README says it
"certifies one configuration on one part at one moment"; this tool certifies the
artefact and says nothing about the moment.

### 6.2 The other necessary failures

* Run-time `FLASH_ACR` writes. The G474 gives up ST's key at `0x704`,
  `0x104` *and* `0x004`, so for this channel the setting mostly changes the
  trace count - but on the same part `CMOX_AES_SMALL` is 0/16 with `DCEN` on and
  16/16 with it off ([`ST_CRYPTOLIB.md`](../../research/exposure/ST_CRYPTOLIB.md) §4b). Which
  way a given build lands is a register write the binary may make conditionally,
  in an interrupt, or not at all.
* MPU configuration. On an M7 the difference between `CACHED_RAM` and `SAFE`
  can be an MPU region attribute set at run time. The tool reports the address's
  *default* attributes.
* A bootloader that relocates. Everything here is anchored on a flash base
  taken from the vector table. An image that a first-stage loader copies to RAM,
  or that XIPs from external QSPI at `0x9000_0000`, needs `--base` and the
  addresses are otherwise wrong. The tool says so when there is no vector table
  at offset 0 rather than silently assuming `0x0800_0000`.
* Position-independent code. If table bases are computed as
  `PC + offset` there is no absolute literal. None of this corpus is PIC; the
  group-relocation test (§3.4) would find nothing and the tool would return
  `UNDETERMINED`. Untested, and stated as untested.
* Tables built at run time. `sboot` with `RIJNDAEL_ROM_SBOXES=0` computes
  its S-box into `.bss` at start-up: there are no table bytes in the image at
  all, `fwscan` and `placement` both return NO-TABLES, and hardware agrees
  (0/16). That is the right answer *here*, because a computed table lands in
  RAM - but "no tables in the image" would be the wrong basis for a clean bill
  of health on a part where the RAM is itself cached.
* Packed / encrypted images. `fwscan --decompress` exists for a reason
  (ST-LINK firmware is RLE-packed after decryption). `placement` inherits the
  problem and not the workaround: it works on the unpacked image, and on a
  packed one it will simply find nothing.
* A countermeasure applied to the tables. `fw_f4_rsm` and `fw_f4_masked`
  both keep a plain S-box in flash - the deliberate positive control - and both
  recover 0/16 on the masked path. The tables are in flash; the *index* is
  masked. A placement tool sees the bytes and the address and cannot tell those
  two cases apart; only the *masked* variants of the tables would distinguish
  them, and matching those is a different fingerprinting problem.

## 7. Does `fwscan` still do its job?

Re-run over all 38 images, not just the four in `tests/test_fwscan.py`. It
reproduces the layout on every one, and there is no image it mis-triages:
every build whose ELF has AES tables has them reported, and the three builds
whose ELF has none (`BearSSL aes_ct`, `OpenSSL` CT, `sboot ROM_SBOX=0`) come
back clean.

Also re-run over the five held-out builds of §5.3: `fw_h7` and `fw_g4_ctguard`
report the 4-table + S-box layout at the addresses their ELFs confirm;
`fw_h7_cache`, `fw_l5_cache` and `fw_nrf_probe` (cache-geometry probes with no
cipher) come back clean. `find_vector_table` also reports the nRF52840's flash
base as `0x0000_0000` correctly, without being told the part.

Four observations worth recording:

1. `sboot ROM_SBOX=0` is a true negative that looks like a miss.
   `SBOOT_RESULTS.md` headlines "16/16 on-chip", so a reader scoring `fwscan`
   against that line would score it a false negative. It is not: the 16/16
   requires `RIJNDAEL_ROM_SBOXES=1`, and the binary checked into
   `rigs/fw_sboot/` is built with `=0`, which *computes* the S-box into
   `.bss`. Building both variants settles it - `ROM_SBOX=1` is reported, and is
   the one that leaks. The lesson is that a corpus label has to name the build
   flag, not the project.
2. `Rcon` alone is not a signal of anything. It is present in tiny-AES-c,
   GmSSL, Nettle, `fw_f4_rsm`, `fw_f3_scode`, `fw_f7_rsm` - and in BearSSL
   `aes_ct`, which has no tables at all. `fwscan`'s verdict text already uses
   it only as "AES is compiled in", which is the right strength.
3. wolfSSL default and OpenSSL default report `sbox=False`. Both derive the
   last round from the T-tables rather than carrying a separate byte S-box, so
   there is nothing to find. Consistent with ST's 1T construction, where
   `line_shift_last = 1` was predicted from the same observation.
4. `fwscan` cannot see placement, by construction - and its address column
   quietly says the wrong thing. On the ST matched pair, `fwscan`'s four
   verdict lines are word-for-word identical between the build that gives up
   a key and the build that reads `sd = 0.00`:

   ```
   => single T-table (Te2) - the compact build. Leaks the full key AND is
      round-2 recoverable ...
   => decryption T-table(s) present (Td2) - 1 KB of inverse tables in flash ...
   ```

   The only difference is the offsets, and that difference is a trap rather than
   a signal: `fwscan` prints `@ base + offset`, which for the *fixed* build is
   `0x080019e0` - the load address of a table that lives at `0x20000000`.
   The phrase "1 KB of inverse tables in flash" is, on that image, false.

   This is not a defect to fix in `fwscan`: the answer needs a copy loop, a
   literal pool and a part memory map, which is a different tool. But it is the
   sharpest statement of why that tool is needed, and `placement`'s output
   should be preferred wherever the two disagree about an address.

## 8. How this sits against existing constant-time tooling

Positioning, based on reading the tools' papers and repositories rather than
running them. Claims about what a tool does are limited to what those documents
say; where a source could not be read it is marked.

The distinction is sharp and it is the reason this module exists. The
established tools ask *"is the algorithm constant-time?"*. The failure this
project is about is *"the algorithm is fine and the deployment is not"*. A
table-based AES is known non-constant-time - every tool below would flag it,
correctly, in one line - and yet `st_flash.bin` and `st_cta.bin` are the same
library, the same source, the same instructions, and one gives up a key while
the other reads `sd = 0.00`. Nothing in the algorithm distinguishes them. One
linker line does.

| tool | consumes | static/dynamic | decides | models *where data lives*? |
|---|---|---|---|---|
| dudect | running binary on the real target | dynamic, statistical (Welch *t*) | are timings distinguishable between input classes, *here, now* | models nothing - its selling point is "no modeling of hardware behavior". Flash effects are *in* the measurement but never attributed |
| ctgrind / Valgrind taint, TIMECOP | binary + source annotations | dynamic taint | does any branch or *address* derive from a secret | checks the address value; no timing model, no memory hierarchy |
| ct-verif | optimised LLVM IR | static, deductive (sound) | control flow + addresses secret-independent, modulo declared public outputs | abstract "leak the branch, leak the address"; pre-codegen, so it cannot even see final addresses |
| BINSEC/Rel | stripped binaries (x86, ARM) | static, relational symbolic execution | same policy, at machine level | concrete addresses in a flat symbolic memory; no cache, no latency, no regions |
| Microwalk / -CI | binaries (Pin), JS, QEMU | dynamic, quantitative (mutual information) | how many bits the access sequence leaks, localised to code | a configurable *address-granularity* knob (discard low log₂g bits) - the closest stand-in for a line size in the dynamic tools, and still just truncation |
| CacheAudit | 32-bit x86 binary + a cache configuration | static, abstract interpretation | an upper bound on bits leaked to cache adversaries | yes, and it is the closest thing here - a classic set-associative cache parameterised by size / line size / associativity / LRU-FIFO-PLRU, optional separate I-cache |
| Constantine | C/C++ → LLVM bitcode | hardening compiler, taint-profiled | linearises secret-dependent control flow, loops and accesses | "touch everything" is defined over the *program's* data structures; where the linker puts them is out of scope |
| Binsec/Haunted, Abacus, CaSym, CacheFix | binaries / LLVM IR | mixed | speculative CT; bits-leaked estimates; cache-aware symbolic execution | CaSym and CacheFix also take a cache model - all CPU data caches, x86/desktop |

None of them models an MCU flash accelerator, flash wait states, a prefetch or
row-latch buffer, or a section placement decided by a linker script. That is a
negative-search result over the two standing catalogues (the CROCS `ct-tools`
catalogue, and Jancar's survey of the state of constant-time tooling), not a
proof of non-existence - but it is a well-supported one, and the closest
approximations are worth naming precisely:

* CacheAudit is the only family that takes a memory-system configuration as
  an *input*. Its model is a CPU set-associative cache, not a flash interface:
  there is no wait-state parameter, no notion of one region having a different
  latency from another, and therefore no way to express "this table is in
  flash and that one is in SRAM" - which is the entire question here. An ART
  is structurally suggestive (lines, hits, misses) but this repo's own G4
  measurements are the counter-example: the key falls with prefetch, I-cache
  and D-cache all disabled, because the array still returns a 64-bit word.
  A pure cache model has nothing to say about that configuration.
* dudect captures the effect empirically, since it measures the real device
   -  and would, correctly, fail both ST builds' *algorithm* and pass neither on
  the strength of a linker change it cannot see. It also requires the device,
  the key harness and 10⁵-ish executions; `placement` runs on a download.
* ELMO\* / Rosita are genuinely device-accurate Cortex-M models, but of
  *power*, not fetch latency, and not of placement.

Two honest consequences of that positioning:

1. This module is not a constant-time verifier and must not be read as one.
   It decides one predicate - *will these table bytes be read through the flash
   interface*  -  over an artefact, with a part-specific memory map. `fw_f4_rsm`
   and `fw_f4_masked` read masked tables out of flash and recover 0/16; a
   placement tool cannot tell those from an unmasked build, and §5.2 scores them
   as false positives rather than explaining them away.
2. The gap is not academic; it is where the vendor guidance already lives.
   ST's own advice is a *linker-level* discipline - "map objects labelled
   `CMOX_CTA_PROTECTED_DATA` onto the desired non-cacheable memory" - and
   nothing in the toolchain checks it. §4.1 is a twenty-line check that audits
   2 277 scripts in a second and reports zero compliant. That is the shape of
   the missing tool: not another CT verifier, a deployment linter.

## 9. Using it

```bash
# exact, from a linked image
python -m flashleak placement rigs/fw_g4_st/fw.elf --part g4

# inferred, from a vendor .bin and nothing else
python -m flashleak placement firmware.bin --part f4

# conditional, from an archive - and check the linker script for the rule
python -m flashleak placement libSTM32Cryptographic_CM4.a --part g4 \
       --ld my_project/STM32G474RETX_FLASH.ld

# what memory map is it using?
python -m flashleak placement x --list-parts

# a whole directory
python -m flashleak placement build/ --part h7 --quiet

# regenerate the numbers in §5
python research/placement_corpus.py --root /path/to/corpus
```

### Files

| file | what |
|---|---|
| [`flashwhisperer/flashleak/placement.py`](../flashleak/placement.py) | the module: part maps, ELF/`ar` readers, the Thumb decoders, the three artefact cases, the linker-script check, the CLI |
| [`flashwhisperer/tests/test_placement.py`](../tests/test_placement.py) | 41 tests: decoders, a synthetic matched pair, the repo's committed firmware, the CI gate |
| [`research/placement_corpus.py`](../../research/placement_corpus.py) | the 38 labels and the two confusion matrices of §5 |

### 9.1 As a CI gate - the "deployment linter" of §8, concretely

By default it reports and exits 0. `--fail-on exposed` turns it into a gate, and
`--json` gives a machine-readable record to diff between builds:

```bash
python -m flashleak placement build/fw.elf --part g4 \
       --ld link.ld --section CMOX_CTA_PROTECTED_DATA \
       --fail-on exposed --json placement.json
```

Three cases, and the middle one is the real failure mode:

| | exit |
|---|---|
| a build whose tables resolve to flash | 1 |
| ST's archive + a linker script that does not place `CMOX_CTA_PROTECTED_DATA` | 1 |
| ST's archive + `link_cta.ld` | 0 |

That middle row is the point. It is one line in a CI file, it runs in a second,
and it is the check that 2 277 of ST's own linker scripts would fail. A
*placement* regression - the one that changes no ciphertext and breaks no test  - 
is exactly the kind of thing a build gate is for. `--fail-on unknown` is the
stricter setting: it also fails an artefact the tool could not settle, which is
the right posture for a vendor blob you are about to ship.

Tests: `python -m pytest tests/test_placement.py -q` - 41 tests, no hardware and
no toolchain. The unit tests build a synthetic matched pair in Python: the
same S-box bytes at the same image offset, once as `.rodata` in flash and once
as a `.data` initialiser bound for RAM, with a real Thumb `LDR` literal pool. So
the discrimination the raw-`.bin` path exists to make is tested even where the
firmware corpus is not present. The 38-artefact corpus in §5 needs WSL and an
ARM toolchain to rebuild and is not part of the suite.

## 10. References for §8

Read for this section; not run.

- O. Reparaz, J. Balasch, I. Verbauwhede, *Dude, is my code constant time?*,
  DATE 2017 (ePrint 2016/1123); `github.com/oreparaz/dudect`.
- A. Langley, ctgrind; `github.com/agl/ctgrind`. TIMECOP (SUPERCOP) applies
  the same poison/unpoison idea at scale.
- J. B. Almeida, M. Barbosa, G. Barthe, F. Dupressoir, M. Emmi, *Verifying
  Constant-Time Implementations*, USENIX Security 2016.
- L.-A. Daniel, S. Bardin, T. Rezk, *Binsec/Rel: Efficient Relational Symbolic
  Execution for Constant-Time at Binary-Level*, IEEE S&P 2020 (arXiv:1912.08788);
  and *Hunting the Haunter*, NDSS 2021, for the speculative extension.
- J. Wichelmann, A. Moghimi, T. Eisenbarth, B. Sunar, *MicroWalk*, ACSAC 2018
  (arXiv:1808.05575); *Microwalk-CI*, ACM CCS 2022 (arXiv:2208.14942).
- G. Doychev, D. Feld, B. Köpf, L. Mauborgne, J. Reineke, *CacheAudit: A Tool for
  the Static Analysis of Cache Side Channels*, USENIX Security 2013
  (ePrint 2013/253); cache parameters as documented in
  `github.com/cacheaudit/cacheaudit`.
- P. Borrello, D. C. D'Elia, L. Querzoni, C. Giuffrida, *Constantine*, ACM CCS
  2021 (arXiv:2104.10749).
- Catalogues: CROCS Masaryk ct-tools (`crocs-muni.github.io/ct-tools/`);
  J. Jancar, *The state of tooling for verifying constant-timeness of
  cryptographic implementations* (`neuromancer.sk/article/26`).
- ST, *Security: Secure usage of the Cryptographic Library* (wiki.st.com) - the
  source of the `CMOX_CTA_PROTECTED_DATA` rule audited in §4.1.

Flagged as unverified: the paper-body threat models of Constantine and
CacheAudit (PDFs would not render for the search); the ct-verif repository's
current toolchain details, taken from the paper and the catalogues rather than
the repo.
