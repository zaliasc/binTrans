	.file	"test.c"
	.option nopic
	.attribute arch, "rv32i2p0"
	.attribute unaligned_access, 0
	.attribute stack_align, 16
	.text
	.align	2
	.globl	main
	.type	main, @function
main:
	addi	sp,sp,-48
	sw	ra,44(sp)
	sw	s0,40(sp)
	addi	s0,sp,48
	call	mem_udp_init
	addi	a5,s0,-40
	mv	a0,a5
	call	prepare_xdp_md
	addi	a5,s0,-40
	mv	a0,a5
	call	xdp_prog
	sw	a0,-20(s0)
	li	a5,0
	mv	a0,a5
	lw	ra,44(sp)
	lw	s0,40(sp)
	addi	sp,sp,48
	jr	ra
	.size	main, .-main
	.align	2
	.globl	mem_udp_init
	.type	mem_udp_init, @function
mem_udp_init:
	addi	sp,sp,-32
	sw	s0,28(sp)
	addi	s0,sp,32
	li	a5,305397760
	sw	a5,-20(s0)
	lw	a5,-20(s0)
	lbu	a4,12(a5)
	andi	a4,a4,0
	sb	a4,12(a5)
	lbu	a4,13(a5)
	andi	a4,a4,0
	ori	a4,a4,8
	sb	a4,13(a5)
	lw	a5,-20(s0)
	addi	a5,a5,196
	sw	a5,-24(s0)
	lw	a5,-24(s0)
	li	a4,1
	sb	a4,9(a5)
	nop
	lw	s0,28(sp)
	addi	sp,sp,32
	jr	ra
	.size	mem_udp_init, .-mem_udp_init
	.align	2
	.globl	prepare_xdp_md
	.type	prepare_xdp_md, @function
prepare_xdp_md:
	addi	sp,sp,-32
	sw	s0,28(sp)
	addi	s0,sp,32
	sw	a0,-20(s0)
	lw	a5,-20(s0)
	li	a4,305397760
	sw	a4,0(a5)
	lw	a5,-20(s0)
	li	a4,305397760
	sw	a4,4(a5)
	nop
	lw	s0,28(sp)
	addi	sp,sp,32
	jr	ra
	.size	prepare_xdp_md, .-prepare_xdp_md
	.align	2
	.globl	xdp_prog
	.type	xdp_prog, @function
xdp_prog:
	addi	sp,sp,-32
	sw	s0,28(sp)
	addi	s0,sp,32
	sw	a0,-20(s0)
 #APP
# 85 "test.c" 1
	lw a0, -20(s0) #append_tag
# 0 "" 2
 #NO_APP
	nop
	mv	a0,a5
	lw	s0,28(sp)
	addi	sp,sp,32
	jr	ra
	.size	xdp_prog, .-xdp_prog
	.ident	"GCC: (g) 10.2.0"
