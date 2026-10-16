# The split, and what it decided

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

This started as a checklist for a split that hadn't happened. It's now the
record of one that has. It was written inside the research repository,
under `flashwhisperer/docs/`, to say what lifting those five packages out
would take, and everything below marked *decided* answers a question it had
left open. Where the old version and this one disagree, this one happened.

The packages came out on 2026-10-14 with their history, including the
commits from before the reorganisation that first grouped them under a
`flashwhisperer/` directory. That directory is gone again here and the
packages sit at the repository root as they originally did, so no package's
history stops at the move.

## The layering, and what enforces it

| package | imports |
|---|---|
| `flashsim` | none of the others |
| `flashattack` | `flashsim` |
| `flashleak` | `flashattack` |
| `flashmap` | none of the others |
| `flasharb` | none of the others |

Left to right, no back edges. Only `flashmap`'s independence is enforced by
a test (`tests/test_flashmap.py` asserts it imports no crypto); the rest
holds because nothing has broken it yet, which is not the same thing.
Re-measure with

```bash
for pkg in flashsim flashattack flashleak flashmap flasharb; do
  printf "%s -> " $pkg
  grep -rhoE "(from|import) (flashsim|flashattack|flashleak|flashmap|flasharb)" \
    $pkg/*.py | awk '{print $2}' | sort -u | tr '\n' ' '
  echo
done
```

The rule that keeps it true: a package here may not import `serial` at
module level, and may not import a board driver at all. That's why the
board-driving scripts were never allowed into `flashattack`, and why a
campaign that drives hardware can contribute a reusable core to the toolkit
but never move into it wholesale.

## What the split decided

* The name. *Decided: the distribution is `flashwhisperer`.* The old
  version noted that `pyproject.toml` said `flashattack` while the directory
  and the five packages said `flashwhisperer`, and that a release had to
  pick one. It picked the repository's name. The console script stays
  `flashattack = flashattack.cli:main`, since that spelling is in every
  capture script written against it; deprecating it would be a second
  decision and nothing here takes it.

* `conftest.py`. *Decided: this repository has its own copy.* The original
  stayed at the research repository's root, where it still serves
  `demo/oscore/` as well as the package tests, and registering `--runslow`
  in two conftests is an error. With one test tree here, one conftest is
  correct.

* The shims stayed behind, as planned. `hardware/atk_lastround.py`,
  `hardware/aes_ref.py`, `hardware/refaes.py`, `hardware/line_offset.py` and
  `demo/oscore/oracle.py` exist only to keep that repository's callers
  working after their implementations moved into these packages. They aren't
  part of the toolkit and didn't travel.

* The test vectors travelled, as planned: `tests/vectors/*.npz` are small
  and store timing with seed-regenerated material, so the long-run replays
  work here. The campaign captures didn't travel. They're untracked and
  recorded in the research repository's manifest.

* Two tests did not travel. *Decided after measuring, not planned.*
  `test_fw_aes_kat.py` compiles each firmware copy of `aes.c` and
  `test_ctguard.py` compiles `rigs/fw_f4_ctguard`; both test firmware, which
  isn't in this repository. They were removed rather than left as permanent
  skips, since a test that can never run reads as coverage and is not.

* Outward documentation. *Decided: the citations stay, and the README says
  they're citations.* The old version said to decide per link whether to
  inline the number or drop it. Dropping them would delete the provenance of
  every measured claim in the docstrings, and inlining them is a rewrite of
  sixty-odd comments with a real chance of changing a number on the way. So
  they stay as what they are, pointers into the research repository, and the
  README says so once rather than each docstring apologising.

## What the split found that the checklist had not

* Three tests resolved the repository root by DEPTH (`parents[2]`, "tests/
  is two below the root"), which was true under `flashwhisperer/tests/` and
  is one level too high here. A depth-resolved path fails lazily, on
  whichever machine runs it next; these were fixed at the move.

* One capture-replay test loaded its file without the skip guard the rest of
  the module uses, so it failed rather than skipped when the untracked
  captures were absent. Two linker-script tests did the same with firmware
  assets. All now skip, and `FLASHWHISPERER_RIGS` points the firmware ones
  at a firmware checkout.

* A fresh clone checks out CRLF until `.gitattributes` exists, whatever the
  object database holds, if `core.autocrlf` is true. A scripted edit
  matching a two-line pattern then silently matches nothing. See the header
  of [`../.gitattributes`](../.gitattributes).

## What this document does not cover

Whether the split was worth doing. It records what it cost and what it
decided; the argument for it was made elsewhere, and isn't re-made here.
