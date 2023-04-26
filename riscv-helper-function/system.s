main:
        addi    sp,sp,-48
        sw      ra,44(sp)
        sw      s0,40(sp)
        addi    s0,sp,48
        addi    a5,s0,-36
        mv      a0,a5
        call    prepare_xdp_md
        addi    a5,s0,-36
        mv      a0,a5
        call    xdp_prog
        nop
        addi x5, x0, 0x60
        jalr x0, x5, 0
        # jump to the eBPF riscv code (absolute addr)
        # lw      ra,44(sp)
        # lw      s0,40(sp)
        # addi    sp,sp,48
        # jr      ra
prepare_xdp_md:
        addi    sp,sp,-32
        sw      s0,28(sp)
        addi    s0,sp,32
        sw      a0,-20(s0)
        lw      a5,-20(s0)
        li      a4,-256
        sw      a4,0(a5)
        lw      a5,-20(s0)
        li      a4,-1
        sw      a4,4(a5)
        nop
        lw      s0,28(sp)
        addi    sp,sp,32
        jr      ra
.section   .mysection,"ax",@progbits        
xdp_prog:
        addi    sp,sp,-32
        sw      s0,28(sp)
        addi    s0,sp,32
        sw      a0,-20(s0)
        nop
        lw      s0,28(sp)
        addi    sp,sp,32
        jr      ra
        