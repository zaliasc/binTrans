file?=test

compile:
	# riscv64-unknown-elf-gcc -S ${file}.c -o ${file}.s 
	riscv64-unknown-elf-gcc -c ${file}.s -o ${file}.o
	riscv64-unknown-elf-ld -T start.ld -Map output.map -N -o ${file}.elf ${file}.o

gen:
	riscv64-unknown-elf-gcc -S test.c -o test.s -march=rv32i -mabi=ilp32
	