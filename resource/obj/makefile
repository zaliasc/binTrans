
# TARGET -- SECTION
# xdp1 xdp1
# xdp2 xdp1
# xdp_adjust_tail xdp_icmp
# xdp_redirect_map xdp_redirect_map
# xdp_router_ipv4 xdp_router_ipv4
# xdp_rxq_info xdp_prog0
# xdp_tx_iptunnel xdp_tx_iptunnel

XDP_TARGET ?= xdp1
SECTION ?= ${XDP_TARGET}

bytecode:
		readelf -x ${SECTION} ./${XDP_TARGET}_kern.o | grep "0x" | awk '{printf "%s%s\n%s%s\n",$$2,$$3,$$4,$$5}' | grep -v "\." > ../bytecode/${XDP_TARGET}.raw

raw:
	readelf -x xdp1 ./xdp1_kern.o | grep "0x" | awk '{printf "%s%s\n%s%s\n",$$2,$$3,$$4,$$5}' | grep -v "\." >> ../bytecode/xdp1.raw
	readelf -x xdp1 ./xdp2_kern.o | grep "0x" | awk '{printf "%s%s\n%s%s\n",$$2,$$3,$$4,$$5}' | grep -v "\." >> ../bytecode/xdp2.raw
	readelf -x xdp_icmp ./xdp_adjust_tail_kern.o | grep "0x" | awk '{printf "%s%s\n%s%s\n",$$2,$$3,$$4,$$5}' | grep -v "\." >> ../bytecode/xdp_adjust_tail.raw
	readelf -x xdp_redirect_map ./xdp_redirect_map_kern.o | grep "0x" | awk '{printf "%s%s\n%s%s\n",$$2,$$3,$$4,$$5}' | grep -v "\." >> ../bytecode/xdp_redirect_map.raw
	readelf -x xdp_router_ipv4 ./xdp_router_ipv4_kern.o | grep "0x" | awk '{printf "%s%s\n%s%s\n",$$2,$$3,$$4,$$5}' | grep -v "\." >> ../bytecode/xdp_router_ipv4.raw
	readelf -x xdp_prog0 ./xdp_rxq_info_kern.o | grep "0x" | awk '{printf "%s%s\n%s%s\n",$$2,$$3,$$4,$$5}' | grep -v "\." >> ../bytecode/xdp_rxq_info.raw
	readelf -x xdp_tx_iptunnel ./xdp_tx_iptunnel_kern.o | grep "0x" | awk '{printf "%s%s\n%s%s\n",$$2,$$3,$$4,$$5}' | grep -v "\." >> ../bytecode/xdp_tx_iptunnel.raw


