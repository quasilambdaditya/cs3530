CLANG ?= clang
BPFTOOL ?= bpftool
CXX ?= g++
PKG_CONFIG ?= pkg-config

BUILD := build
BPF_OBJ := $(BUILD)/count_packets.bpf.o
SKEL := $(BUILD)/count_packets.skel.h
AGENT := $(BUILD)/tc-counter
TEST := $(BUILD)/count_packets_test
MESHLINK_BPF_OBJ := $(BUILD)/meshlink.bpf.o
MESHLINK_SKEL := $(BUILD)/meshlink.skel.h
M2_AGENT := $(BUILD)/m2
MESHLINK_DAEMON := $(BUILD)/meshlinkd
MESHLINK_TEST := $(BUILD)/meshlink_test

ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
BPF_ARCH := x86
else ifeq ($(ARCH),aarch64)
BPF_ARCH := arm64
else
BPF_ARCH := $(ARCH)
endif

LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf)
BPF_SYS_INCLUDES := -I/usr/include/$(ARCH)-linux-gnu

.PHONY: all test test-meshlink clean

# Build the BPF object, skeleton, loader, test, M2 agent, MeshLink daemon, and MeshLink test.
all: $(AGENT) $(TEST) $(M2_AGENT) $(MESHLINK_DAEMON) $(MESHLINK_TEST)

$(BUILD):
	mkdir -p $@

# Compile the eBPF C program.
$(BPF_OBJ): bpf/count_packets.bpf.c | $(BUILD)
	$(CLANG) -g -O2 -target bpf \
		-D__TARGET_ARCH_$(BPF_ARCH) \
		$(BPF_SYS_INCLUDES) \
		-c $< -o $@

# Generate the libbpf skeleton header.
$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Build the live TC counter.
$(AGENT): src/agent/main.cpp $(SKEL)
	$(CXX) -std=c++17 -O2 -Wall -Wextra \
		-I$(BUILD) $(LIBBPF_CFLAGS) \
		$< -o $@ $(LIBBPF_LIBS) -pthread

# Build the GoogleTest binary.
$(TEST): tests/count_packets_test.cpp $(SKEL)
	$(CXX) -std=c++17 -O2 -Wall -Wextra \
		-I$(BUILD) $(LIBBPF_CFLAGS) \
		$< -o $@ $(LIBBPF_LIBS) -lgtest -lgtest_main -pthread

# Compile the MeshLink eBPF program.
$(MESHLINK_BPF_OBJ): bpf/meshlink.bpf.c inc/common.h | $(BUILD)
	$(CLANG) -g -O2 -target bpf \
		-D__TARGET_ARCH_$(BPF_ARCH) \
		-Iinc $(BPF_SYS_INCLUDES) \
		-c $< -o $@

# Generate the MeshLink skeleton header.
$(MESHLINK_SKEL): $(MESHLINK_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Build the M2 MeshLink agent.
$(M2_AGENT): src/agent/m2.cpp $(MESHLINK_SKEL) inc/common.h
	$(CXX) -std=c++17 -O2 -Wall -Wextra \
		-I$(BUILD) -Iinc $(LIBBPF_CFLAGS) \
		$< -o $@ $(LIBBPF_LIBS) -pthread

# Build the MeshLink control plane daemon.
$(MESHLINK_DAEMON): src/agent/meshlinkd.cpp $(MESHLINK_SKEL) inc/common.h
	$(CXX) -std=c++17 -O2 -Wall -Wextra \
		-I$(BUILD) -Iinc $(LIBBPF_CFLAGS) \
		$< -o $@ $(LIBBPF_LIBS) -pthread

# Build the MeshLink GoogleTest binary.
$(MESHLINK_TEST): tests/meshlink_test.cpp $(MESHLINK_SKEL) inc/common.h
	$(CXX) -std=c++17 -O2 -Wall -Wextra \
		-I$(BUILD) -Iinc $(LIBBPF_CFLAGS) \
		$< -o $@ $(LIBBPF_LIBS) -lgtest -lgtest_main -pthread

# Run tests as root, since loading BPF generally requires privileges.
test: $(MESHLINK_TEST)
	@if [ "$$(id -u)" -eq 0 ]; then \
		./$(MESHLINK_TEST); \
	else \
		sudo ./$(MESHLINK_TEST); \
	fi

test-meshlink: $(MESHLINK_TEST)
	@if [ "$$(id -u)" -eq 0 ]; then \
		./$(MESHLINK_TEST); \
	else \
		sudo ./$(MESHLINK_TEST); \
	fi

clean:
	rm -rf $(BUILD)
