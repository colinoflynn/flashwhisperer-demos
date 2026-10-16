# Dependencies: what is pinned, how, and why not a submodule update

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

```bash
./deps/fetch.sh --tools          # flashwhisperer + ethtimer. Enough for demo 00
./deps/fetch.sh                  # those plus every vendor SDK a demo builds
./deps/fetch.sh x-cube-subg2     # just one
./deps/fetch.sh --size           # what is on disk
pip install -e deps/flashwhisperer -e deps/ethtimer
```

[`PINS`](PINS) is the register: name, URL, commit, version, kind. It carries
the reason each version is the one it is, which is not a detail - one of them
is a line where the latest release of a library does not contain the cipher
this measures at all.

Nothing is vendored and nothing here is patched. Every dependency is upstream's
own bytes at a stated commit, and what a victim changes lives in that demo's
`victim/` directory. `../tools/verify.sh` checks that rather than asserting it.

## Why `git submodule update --init` is the wrong command here

It clones the default **branch**, at depth 1 if you ask, and several pins here
are release commits that are not on it. You get a checkout of some other
version under the right directory name - which for a vendor SDK compiles
cleanly and measures something else. `fetch.sh` instead gives each dependency
an empty repository with one remote, a sparse checkout of the directories
something here actually compiles, and a single depth-1 fetch of the pinned
commit.

`git submodule add` is wrong for a second reason: it clones whole histories,
STM32CubeF4 and RIOT are enormous, and nothing here needs the history.

The `.gitmodules` entries are still real, and where the parent records a
gitlink it agrees with `PINS` - `verify.sh` checks that, because a clone would
otherwise get a different version than this checkout has.

Only the two `tool` dependencies carry a committed gitlink, because they are
the ones every clone needs. The vendor SDKs are pinned in `PINS` and nowhere
else, deliberately: a gitlink for a tree you have fetched and nobody else has
shows up as a diff in your working copy for no gain, and `PINS` is what
`fetch.sh` reads. So `PINS` is the authority, and `git add -A` after a fetch is
not supposed to add anything under `deps/`.

## The vendor's own code, as the vendor ships it

The victims compile the lwIP, mbedTLS, HAL and CMSIS **that the vendor package
ships**, not upstream releases of those libraries. That is deliberate and it is
the whole claim: a device built the way the vendor's own example builds it gives
up its key. So there is no upstream Mbed-TLS pin in this repository even though
three victims use Mbed-TLS.

That is the opposite of what
[flashwhisperer-crypto-eval](https://github.com/colinoflynn/flashwhisperer-crypto-eval)
wants, where the library is the variable and is pinned upstream, one commit per
measurement. The two repositories answer different questions and their `PINS`
files are not interchangeable.

## The one that is not a vendor repository

X-CUBE-SBSFU. There is no `STMicroelectronics/x-cube-sbsfu` (404, checked
2026-09-26) and ST ships it as a zip, so `deps/sbsfu` is a third-party mirror
pinned to a commit, with the release version asserted out of its own
`Release_Notes.html`. A mirror can be force-pushed or deleted; a commit SHA
cannot change under you, and the assertion fails loudly if the tree is not the
one the ports were written against. It is gitignored and has no `.gitmodules`
entry, because a gitlink there would read as though ST published it.

Harmony 3 is not a clone at all: MPLAB X's Content Manager installs it one
versioned component at a time. Its versions get recorded with that demo.

## Toolchains, which are yours to install

| | |
|---|---|
| `arm-none-eabi-gcc` | every ARM victim and instrument. A codegen difference changes the instruction stream, and the instruction stream is part of what is measured, so a build from a different compiler is not a reproduction of the capture - it is a new capture |
| MPLAB X **v6.20** and XC32 | the PIC32MZ victim. Not v6.25 or later: that dropped support for the board's Gen-3 PKOB debugger |
| Microchip device packs | the SAM D21. Small surface, because that port hand-wrote its HAL rather than pulling in a framework |
| `python`, `numpy` | the analysis. `pip install -e deps/flashwhisperer` brings what it needs |

## What a fetch does not do

* It does not check that a pinned commit is still published upstream. A force
  push or a deleted mirror leaves a checkout here that nobody else can
  reproduce, and only a fresh clone on another machine finds that.
* It does not install a toolchain, and it does not check the one you have.
* It does not patch anything.
