# RIOT's FIDO2 CTAP2 authenticator, built for the nRF52840 **Dongle**.
#
# Why a separate rig from the nRF52840-DK the campaign used: the Dongle is the realistic
# target. It has no on-board debugger, so neither an attacker nor this bench can reset it
# over SWD or write its `cred_key`. Everything goes through the USB port, which is the
# threat model the campaign claims. README.md says what that changes.
#
#   make                 user presence ENABLED  (the shipping default)
#   make DISABLE_UP=1    user presence disabled (what RIOT's own test app does)
#   make flash PORT=COMn flash over DFU -- no debugger needed
#
# The build happens IN RIOT's own app directory, with its Makefile patched and restored
# around it. Building out of tree was tried first and is not worth it: RIOT's test apps
# chain relative includes (`../Makefile.sys_common` -> `../../Makefile.tests_common`), so
# a staged copy has to sit at exactly the right depth or the chain breaks. Patching one
# line in a scratch checkout is the smaller evil, and `restore` runs even on failure.
RIOT ?= ../../../riot
# fido2_ctap_hid, NOT fido2_ctap. The latter is a unit-test app whose own docstring says
# it "tests CTAP functionality WITHOUT transport layer" -- it drives the CTAP layer with
# canned CBOR and enumerates no HID interface at all, so there is nothing to attack. That
# mistake was caught by flashing a Dongle and finding only a CDC serial endpoint.
# fido2_ctap_hid is what the campaign's DK victim ran, and it lists nrf52840dongle in its
# own BOARDS_SUPPORTED.
APP  ?= $(RIOT)/tests/sys/fido2_ctap_hid
BOARD ?= nrf52840dongle
DISABLE_UP ?= 0

all:
	@# A previous run killed mid-build leaves the backup behind, and RIOT's Makefile
	@# patched. Restore it first, or the next `cp` overwrites the pristine copy with the
	@# patched one and the original is gone for good.
	@if [ -f $(APP)/Makefile.rigbak ]; then \
	   echo "  restoring a stale Makefile.rigbak from an interrupted run"; \
	   mv $(APP)/Makefile.rigbak $(APP)/Makefile; fi
	@cp $(APP)/Makefile $(APP)/Makefile.rigbak
	@if [ "$(DISABLE_UP)" != "1" ]; then \
	   sed -i '/CONFIG_FIDO2_CTAP_DISABLE_UP/d' $(APP)/Makefile; \
	   echo "  user presence ENABLED (the shipping default)"; \
	 else \
	   echo "  user presence DISABLED (RIOT's test default)"; fi
	@$(MAKE) -C $(APP) BOARD=$(BOARD) || ( \
	   mv $(APP)/Makefile.rigbak $(APP)/Makefile; exit 1 )
	@mv $(APP)/Makefile.rigbak $(APP)/Makefile
	@echo "  artefact: $(APP)/bin/$(BOARD)/tests_fido2_ctap.hex"

flash:
	$(MAKE) -C $(APP) BOARD=$(BOARD) flash PORT=$(PORT)

clean:
	$(MAKE) -C $(APP) BOARD=$(BOARD) clean

.PHONY: all flash clean
