# riscv64-unknown-elf-gcc -march=rv32imc -mabi=ilp32
riscv64-unknown-elf-gcc -S test.c -o test.s -march=rv32i -mabi=ilp32
line=grep -rn "append_tag" test.s | cut -d : -f1
sed -i "$line r xdp_prog.s" test.s