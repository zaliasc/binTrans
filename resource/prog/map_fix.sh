target=xdp11

# 64      |  32     | 32
# offset |  type | index

# - 低 64 位是 offset，用于关联当前 entry 对应代码 section 中具体的指令。代码 section 指令位置到其 section 起始地址，偏移的长度 offset 等于这个 offset；
# - 高 64 位是 Info，其中的低 32 位对应重定位 symbol 的 type，高 32 位对应重定位 symbol 的index（在 symbol 表的 id）。

# 大小端转换
little_to_big_endian() {
  echo ${1:6:2}${1:4:2}${1:2:2}${1:0:2}
}

section_index=`readelf -S xdp11_kern.o | grep .relxdp1 | awk -F ']' '{print $1}' | sed 's/[^0-9]//g'`

echo ${section_index}

symbol_index=`readelf -x 4 xdp11_kern.o | grep 0x | awk '{print $5}'`
symbol_hex=`little_to_big_endian ${symbol_index}`
symbol_dec=$((16#$symbol_hex))
symbol=`readelf -s xdp11_kern.o | grep ${symbol_dec} | awk '{printf $NF}'`

echo ${symbol}

inst_offset_h=`readelf -x 4 xdp11_kern.o | grep 0x | awk '{print $3}'`
inst_offset_l=`readelf -x 4 xdp11_kern.o | grep 0x | awk '{print $2}'`
inst_offset=`little_to_big_endian ${inst_offset_l}+little_to_big_endian ${inst_offset_h}`

echo ${inst_offset}

  