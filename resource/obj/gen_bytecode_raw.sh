#!/bin/sh

# TARGET -- SECTION
# xdp1 xdp1
# xdp2 xdp1
# xdp_adjust_tail xdp_icmp
# xdp_redirect_map xdp_redirect_map
# xdp_router_ipv4 xdp_router_ipv4
# xdp_rxq_info xdp_prog0
# xdp_tx_iptunnel xdp_tx_iptunnel

# for file in `ls ./*.o`
# do
#   llvm-objdump-10 -S ${file} > ../bytecode/${file%_kern.o}.bytecode
# done 

target=( xdp1 xdp2 xdp_adjust_tail xdp_redirect_map xdp_router_ipv4 xdp_rxq_info xdp_tx_iptunnel )
section=( xdp1 xdp1 xdp_icmp xdp_redirect_map xdp_router_ipv4 xdp_prog0 xdp_tx_iptunnel )

for(( i=0;i<${#target[@]};i++)) 
do
llvm-objdump-10 -S ./${target[i]}_kern.o >> ../bytecode/${target[i]}.bytecode
readelf -x ${section[i]} ./${target[i]}_kern.o | grep "0x" | awk '{printf "%s%s\n%s%s\n",$2,$3,$4,$5}' | grep -v "\." >> ../bytecode/${target[i]}.raw
done












