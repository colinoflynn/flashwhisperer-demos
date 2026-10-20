# A stock RIOT GNRC node that answers ICMPv6 echo with link-layer security on.
#
# NOTHING IN RIOT IS PATCHED BY THIS BUILD. The link key is a build flag, the
# channel and the PAN id are RIOT's own defaults, and the application is a
# shell and a message queue. `diff` this directory against a fresh
# ./deps/fetch.sh and the only new files are the ones here.
APPLICATION = riot_802154_echo
BOARD ?= nrf52840dk
RIOTBASE ?= $(CURDIR)/../../../deps/riot

# The pin the demo's line numbers, table address and vectors are against.
RIOT_PIN = f59dcdace51d34218c24339d299ebc3777ec45bc

DEVELHELP ?= 0
QUIET ?= 1

# The module names are this pin's: `netdev_default`, not the
# `gnrc_netdev_default` of older trees. The set is the one
# examples/networking/gnrc/minimal uses, plus a shell to read the address off
# and ieee802154_security, which is the module under test.
USEMODULE += netdev_default
USEMODULE += auto_init_gnrc_netif
USEMODULE += gnrc_ipv6_default
USEMODULE += gnrc_icmpv6_echo
USEMODULE += shell
USEMODULE += shell_cmds_default
USEMODULE += ieee802154_security

# The link key, and the only thing this build changes about RIOT's behaviour.
# CONFIG_IEEE802154_SEC_DEFAULT_KEY is guarded by `#if !defined` at
# sys/include/net/ieee802154_security.h:105, so defining it from here is the
# supported way in and needs no edit to RIOT. Without it the victim runs on
# RIOT's own published default, the string "pizza_margherita".
KEY_HEADER ?= $(CURDIR)/demo_key.h
ifneq (,$(wildcard $(KEY_HEADER)))
  CFLAGS += -DCONFIG_IEEE802154_SEC_DEFAULT_KEY=DEMO_KEY_STRING
  CFLAGS += -include $(KEY_HEADER)
endif

# Say so loudly if the checkout is not the commit this demo was measured on.
# A GNRC build against a different RIOT still builds and still answers pings;
# it just is not the victim any number in this demo refers to.
CHECK_PIN := $(shell git -C $(RIOTBASE) rev-parse HEAD 2>/dev/null)
ifneq ($(CHECK_PIN),)
  ifneq ($(CHECK_PIN),$(RIOT_PIN))
    $(warning RIOTBASE is at $(CHECK_PIN), not the pinned $(RIOT_PIN).)
    $(warning Run ./deps/fetch.sh riot, or expect the table address to move.)
  endif
endif

include $(RIOTBASE)/Makefile.include
