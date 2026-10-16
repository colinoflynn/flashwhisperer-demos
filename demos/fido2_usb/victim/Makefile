# Arm B: RIOT's OWN CTAP2 authenticator, unmodified, on the nRF52840-DK.
#
# There is no firmware in this directory on purpose.  The victim is RIOT's
# tests/sys/fido2_ctap_hid exactly as shipped, because a claim about a stock
# authenticator is worth more than a claim about one we wrote -- the same reason
# the 802.15.4 demo attacks ST's own firmware plus 62 lines of guards.
#
#   make RIOTBASE=~/RIOT              build the stock app
#   make RIOTBASE=~/RIOT flash        flash it
#   make RIOTBASE=~/RIOT trigger      apply trigger.patch, then build with the pin
#   make RIOTBASE=~/RIOT untrigger    take the patch back out
#
# RIOT is an external checkout and will not be here forever, so everything this
# rig asserts about it is quoted with file and line in
# ../../the demo README, against a pinned commit.
RIOTBASE ?= $(HOME)/RIOT
BOARD    ?= nrf52840dk
APP       = $(RIOTBASE)/tests/sys/fido2_ctap_hid
RIOT_SHA  = f59dcdace51d34218c24339d299ebc3777ec45bc

# The stock app already disables the user-presence prompt for its own test
# suite (CONFIG_FIDO2_CTAP_DISABLE_UP=1).  We do NOT rely on that: the probe
# sends options.up = false instead, which is a protocol-level choice any client
# may make, so the measurement holds against a build that keeps UP enabled.
# Set UP=keep to build with the prompt live and prove exactly that.
ifeq ($(UP),keep)
  CFLAGS += -DCONFIG_FIDO2_CTAP_DISABLE_UP=0
endif

# CFLAGS goes in the ENVIRONMENT, never as a make argument.  A command-line
# variable assignment overrides every internal assignment in the sub-make, which
# wipes RIOT's own CFLAGS -- including the -DCPU_MODEL_* define its CPU headers
# dispatch on.  The symptom is not a missing flag but
# `cpu_conf.h: #error "The CPU_MODEL of your board is currently not supported"`,
# followed by a hundred undeclared-CMSIS errors, which reads like a broken
# toolchain and is not.  In the environment, RIOT's `CFLAGS +=` appends to ours.
all: check-riot
	env CFLAGS='$(CFLAGS)' $(MAKE) -C $(APP) BOARD=$(BOARD)

flash: check-riot
	env CFLAGS='$(CFLAGS)' $(MAKE) -C $(APP) BOARD=$(BOARD) flash

trigger: check-riot
	cd $(RIOTBASE) && patch -p1 < $(CURDIR)/trigger.patch
	env CFLAGS='$(CFLAGS) -DFW_TRIGGER=1' $(MAKE) -C $(APP) BOARD=$(BOARD)

untrigger: check-riot
	cd $(RIOTBASE) && patch -p1 -R < $(CURDIR)/trigger.patch

check-riot:
	@test -d $(APP) || { echo "no $(APP) -- set RIOTBASE (git clone https://github.com/RIOT-OS/RIOT)"; exit 1; }
	@cd $(RIOTBASE) && test "$$(git rev-parse HEAD)" = "$(RIOT_SHA)" || \
	  echo "WARNING: RIOT is not at $(RIOT_SHA); the line numbers in RIOT_PROTOCOLS.md are quoted against that commit"

.PHONY: all flash trigger untrigger check-riot
