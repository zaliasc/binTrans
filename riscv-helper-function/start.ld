MEMORY
{
	MY_MEMORY (rx) : ORIGIN = 0x30000, LENGTH = 128k
}

SECTIONS {
  . = 0x00000000;
  .text 0x00000000 :
  {
    *(.text)
  }

  .mysection :
  {
    . = ALIGN(4);
    __mysection_start__ = .;
	*(.mysection*)
    __mysection_end__ = .;
  } > MY_MEMORY
}

/* Check if MY_MEMORY usage exceeds MY_MEMORY size */
ASSERT( LENGTH(MY_MEMORY) >= (__mysection_end__ - __mysection_start__), "MY_MEMORY memory overflowed !")
