	.file	"test.c"
	.option nopic
	.attribute arch, "rv64i2p0_m2p0_a2p0_f2p0_d2p0_c2p0"
	.attribute unaligned_access, 0
	.attribute stack_align, 16
	.section	.mysection,"ax",@progbits
	.align	1
	.globl	prepare_xdp_md
	.type	prepare_xdp_md, @function
prepare_xdp_md:
	addi	sp,sp,-32
	sd	s0,24(sp)
	addi	s0,sp,32
	sd	a0,-24(s0)
	ld	a5,-24(s0)
	li	a4,-256
	sw	a4,0(a5)
	ld	a5,-24(s0)
	li	a4,-1
	sw	a4,4(a5)
	nop
	ld	s0,24(sp)
	addi	sp,sp,32
	jr	ra

	.size	prepare_xdp_md, .-prepare_xdp_md
	.section	.mysection,"ax",@progbits
	.align	1
	.globl	xdp_prog
	.type	xdp_prog, @function
xdp_prog:
	addi	sp,sp,-32
	sd	s0,24(sp)
	addi	s0,sp,32
	sd	a0,-24(s0)
	nop
	ld	s0,24(sp)
	addi	sp,sp,32
	jr	ra

	.size	xdp_prog, .-xdp_prog
	.text
	.align	1
	.globl	main
	.type	main, @function
main:
	addi	sp,sp,-48
	sd	ra,40(sp)
	sd	s0,32(sp)
	addi	s0,sp,48
	addi	a5,s0,-40
	mv	a0,a5
	call	prepare_xdp_md
	addi	a5,s0,-40
	mv	a0,a5
	call	xdp_prog
	nop
	ld	ra,40(sp)
	ld	s0,32(sp)
	addi	sp,sp,48
	jr	ra
	.size	main, .-main
	.ident	"GCC: (SiFive GCC-Metal 10.2.0-2020.12.8) 10.2.0"
