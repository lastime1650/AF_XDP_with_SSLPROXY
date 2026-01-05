VCPKG_ROOT    := /root/VATEX/vcpkg
VCPKG_TRIPLET := x64-linux
export PKG_CONFIG_PATH := $(VCPKG_ROOT)/installed/$(VCPKG_TRIPLET)/lib/pkgconfig



CXX     := g++
CLANG   := clang
BPFTOOL := bpftool



COMMON_PACKAGES = PcapPlusPlus fmt rdkafka++ rdkafka liblz4 libzstd zlib openssl libbpf libxdp
COMMON_CXXFLAGS = -O0 -g -w -fpermissive -DOPENSSL_THREADS \
                  $(shell pkg-config --cflags $(COMMON_PACKAGES))

COMMON_LDFLAGS  = -Wl,-rpath,$(VCPKG_ROOT)/installed/$(VCPKG_TRIPLET)/lib -ldl
COMMON_LDLIBS   = $(shell pkg-config --libs $(COMMON_PACKAGES))



BPF_SRCS   := ebpf/xdp_prog.bpf.c
BPF_OBJS   := $(BPF_SRCS:.c=.o)
BPF_SKELS  := $(BPF_SRCS:.c=.skel.h)
BPF_CFLAGS := -O2 -g -Wall -target bpf -I.

APP_TARGET := IPS_APP
APP_SRCS   := main.cpp



.PHONY: all clean
all: $(APP_TARGET)

# eBPF build
%.o: %.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

%.skel.h: %.o
	$(BPFTOOL) gen skeleton $< > $@

# App build (SSLPROXY.hpp 포함)
$(APP_TARGET): $(BPF_SKELS) $(APP_SRCS)
	$(CXX) -std=gnu++20 -D_GNU_SOURCE -I./Network \
	$(COMMON_CXXFLAGS) \
	$(APP_SRCS) -o $@ \
	$(COMMON_LDFLAGS) \
	$(COMMON_LDLIBS) 

# Clean
clean:
	rm -f $(APP_TARGET)
	rm -f $(BPF_OBJS) $(BPF_SKELS)