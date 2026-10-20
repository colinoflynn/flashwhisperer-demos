# The 802.15.4 instrument: a RIOT node that probes and timestamps the air.
#
# Built for the nRF52840 Dongle, which has no debugger of any kind -- the
# attacker gets a USB port and nothing else, which is the point.
#
#   python patch_riot.py <riot-checkout>      # the one hook, bytes preserved
#   make BOARD=nrf52840dongle RIOTBASE=<riot-checkout>
#   make flash PORT=COM_n_                    # nrfutil, over DFU
#   python patch_riot.py <riot-checkout> --restore
APPLICATION = riot802154_stamp
BOARD ?= nrf52840dongle
RIOTBASE ?= $(CURDIR)/../../deps/riot

RIOT_PIN = f59dcdace51d34218c24339d299ebc3777ec45bc

DEVELHELP ?= 0
QUIET ?= 1

USEMODULE += netdev_default
USEMODULE += auto_init_gnrc_netif
USEMODULE += gnrc_ipv6_default
USEMODULE += gnrc_icmpv6_echo
USEMODULE += shell
USEMODULE += shell_cmds_default
USEMODULE += ieee802154_security

# OTA_STAMP turns on the TIMER4 + PPI setup in main.c, the ring in
# radio_stamp.c, and the `ota_radio_end_stamp` call patch_riot.py put in the
# driver. Without it this builds as an ordinary RIOT node.
CFLAGS += -DOTA_STAMP=1
SRC += radio_stamp.c

CHECK_PIN := $(shell git -C $(RIOTBASE) rev-parse HEAD 2>/dev/null)
ifneq ($(CHECK_PIN),)
  ifneq ($(CHECK_PIN),$(RIOT_PIN))
    $(warning RIOTBASE is at $(CHECK_PIN), not the pinned $(RIOT_PIN).)
    $(warning patch_riot.py checks its anchors, so a moved driver fails loudly.)
  endif
endif

include $(RIOTBASE)/Makefile.include
