CONTIKI_PROJECT = la-iot-evidence
all: $(CONTIKI_PROJECT)

CONTIKI ?= /path/to/pinned/contiki-ng
MODULES += os/net/app-layer/coap
MAKE_NET = MAKE_NET_IPV6
MAKE_ROUTING = MAKE_ROUTING_RPL_LITE

# Replace UNSET with the immutable application source hash for a real build.
LA_IOT_BUILD_ID ?= UNSET
CFLAGS += -DLA_IOT_BUILD_ID=\"$(LA_IOT_BUILD_ID)\"

include $(CONTIKI)/Makefile.include
