FRIDA_VERSION ?= 17.9.1
OUTPUT_DIR ?= $(CURDIR)/output
OUTPUT_CLIP_DIR := $(OUTPUT_DIR)/clip

FRIDA_BASE_URL := https://github.com/frida/frida/releases/download/$(FRIDA_VERSION)

ifeq ($(origin FRIDA_CORE_DEVKIT), undefined)
FRIDA_CORE_MANAGED := 1
FRIDA_CORE_DEVKIT := $(CURDIR)/build/frida-core-$(FRIDA_VERSION)
else
FRIDA_CORE_MANAGED := 0
endif

FRIDA_CORE_ARCHIVE_DIR := $(FRIDA_CORE_DEVKIT)/archives
FRIDA_CORE_HEADER := $(FRIDA_CORE_DEVKIT)/frida-core.h
FRIDA_CORE_LIB := $(FRIDA_CORE_DEVKIT)/libfrida-core.a

CPPFLAGS += -I$(FRIDA_CORE_DEVKIT) -I$(FRIDA_CORE_DEVKIT)/include -I$(CURDIR)/clip/vendor/rxi-log -I$(OUTPUT_DIR) -DLOG_USE_COLOR
CFLAGS += -Wall -Os -pipe -g3 -framework IOKit -framework Security

FRIDA_CORE_LDFLAGS := -L$(FRIDA_CORE_DEVKIT) -lfrida-core -lresolv -Wl,-framework,Foundation -Wl,-framework,AppKit -Wl,-dead_strip -Wl,-no_compact_unwind

.DEFAULT_GOAL := all

.PHONY: all clean frida-core FORCE

CLIP_SRCS := $(wildcard clip/*.c) clip/vendor/rxi-log/log.c
EXTENSION_SRCS := clip/extension/main.m clip/extension/window.m clip/extension/corner.m
EXTENSION_OUT := $(OUTPUT_CLIP_DIR)/extension.dylib
CLIP_VENDOR_BRIDGES := clip/vendor/frida-objc-bridge

ifeq ($(FRIDA_CORE_MANAGED),1)
FRIDA_CORE_READY := $(FRIDA_CORE_DEVKIT)/.prepared
else
FRIDA_CORE_READY := $(FRIDA_CORE_HEADER) $(FRIDA_CORE_LIB)
endif

all: $(OUTPUT_CLIP_DIR)/main $(EXTENSION_OUT)

frida-core: $(FRIDA_CORE_READY)

$(OUTPUT_DIR)/.staged:
	rm -rf "$(OUTPUT_CLIP_DIR)"
	mkdir -p "$(OUTPUT_DIR)"
	cp -R "$(CURDIR)/clip" "$(OUTPUT_DIR)/"
	touch $@
CLIP_JS_SRCS := clip/loader.entry.js $(wildcard clip/agent/*.js) $(shell find $(CLIP_VENDOR_BRIDGES) -type f \( -name '*.js' -o -name '*.ts' -o -name 'package.json' \))

FORCE:

$(OUTPUT_DIR)/bundle.h: $(CLIP_JS_SRCS) FORCE
	mkdir -p "$(OUTPUT_DIR)"
	npx --yes frida-compile clip/loader.entry.js -o $(OUTPUT_DIR)/bundle.js
	cd $(OUTPUT_DIR) && xxd -i bundle.js > bundle.h

$(OUTPUT_CLIP_DIR)/main: $(CLIP_SRCS) $(OUTPUT_DIR)/.staged $(FRIDA_CORE_READY) $(OUTPUT_DIR)/bundle.h
	mkdir -p "$(dir $@)"
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(CLIP_SRCS) $(FRIDA_CORE_LDFLAGS) $(LDLIBS)

GTK4_CFLAGS := $(shell pkg-config --cflags gtk4) -framework AppKit
GTK4_LIBS := $(shell pkg-config --libs gtk4)

$(EXTENSION_OUT): $(EXTENSION_SRCS) $(OUTPUT_DIR)/.staged
	mkdir -p "$(dir $@)"
	$(CC) -dynamiclib -arch arm64 $(CPPFLAGS) $(CFLAGS) $(GTK4_CFLAGS) -framework Foundation -o $@ $(EXTENSION_SRCS) $(GTK4_LIBS)

ifeq ($(FRIDA_CORE_MANAGED),1)
$(FRIDA_CORE_DEVKIT)/.prepared: $(FRIDA_CORE_ARCHIVE_DIR)/frida-core-devkit-$(FRIDA_VERSION)-macos-x86_64.tar.xz $(FRIDA_CORE_ARCHIVE_DIR)/frida-core-devkit-$(FRIDA_VERSION)-macos-arm64e.tar.xz $(FRIDA_CORE_ARCHIVE_DIR)/frida-core-devkit-$(FRIDA_VERSION)-macos-arm64.tar.xz
	mkdir -p "$(FRIDA_CORE_DEVKIT)/x86_64" "$(FRIDA_CORE_DEVKIT)/arm64e" "$(FRIDA_CORE_DEVKIT)/arm64"
	tar -xf "$(FRIDA_CORE_ARCHIVE_DIR)/frida-core-devkit-$(FRIDA_VERSION)-macos-x86_64.tar.xz" -C "$(FRIDA_CORE_DEVKIT)/x86_64"
	tar -xf "$(FRIDA_CORE_ARCHIVE_DIR)/frida-core-devkit-$(FRIDA_VERSION)-macos-arm64e.tar.xz" -C "$(FRIDA_CORE_DEVKIT)/arm64e"
	tar -xf "$(FRIDA_CORE_ARCHIVE_DIR)/frida-core-devkit-$(FRIDA_VERSION)-macos-arm64.tar.xz" -C "$(FRIDA_CORE_DEVKIT)/arm64"
	cp "$(FRIDA_CORE_DEVKIT)/x86_64/frida-core.h" "$(FRIDA_CORE_HEADER)"
	lipo -create "$(FRIDA_CORE_DEVKIT)/x86_64/libfrida-core.a" "$(FRIDA_CORE_DEVKIT)/arm64e/libfrida-core.a" "$(FRIDA_CORE_DEVKIT)/arm64/libfrida-core.a" -output "$(FRIDA_CORE_LIB)"
	touch "$@"

$(FRIDA_CORE_ARCHIVE_DIR)/frida-core-devkit-$(FRIDA_VERSION)-macos-%.tar.xz:
	mkdir -p "$(dir $@)"
	curl -L --output "$@" "$(FRIDA_BASE_URL)/$(@F)"
endif

clean:
	rm -rf "$(OUTPUT_DIR)"
ifeq ($(FRIDA_CORE_MANAGED),1)
	rm -rf "$(FRIDA_CORE_DEVKIT)"
endif
