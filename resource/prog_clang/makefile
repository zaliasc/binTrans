XDP_TARGETS ?= xdp2
SEC ?= udp_payload
DEVICE ?= ens33

all: compile raw_byte byte

load:
	sudo ip link set dev ${DEVICE} xdp obj ${XDP_TARGETS}.o sec ${SEC}

unload:
	sudo ip link set dev ${DEVICE} xdp off

show:
	ip link show dev ${DEVICE}

compile:
	clang -g -O2 -target bpf -c ./${XDP_TARGETS}.c -o ${XDP_TARGETS}.o

raw_byte:
	readelf -x ${SEC} ./${XDP_TARGETS}.o | grep "0x" | awk '{printf "%s%s\n%s%s\n",$$2,$$3,$$4,$$5}' | grep -v "\." > ${XDP_TARGETS}.raw

byte:
	llvm-objdump-10 -S ${XDP_TARGETS}.o > ${XDP_TARGETS}.dump

clean:
	rm -rf *.o *.s *.text *.raw *.dump