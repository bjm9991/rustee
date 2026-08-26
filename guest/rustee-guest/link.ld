ENTRY(_start)
SECTIONS {
  . = 0x40000000;
  .text : {
    *(.text.boot)
    *(.text .text.*)
  }
  .rodata : { *(.rodata .rodata.*) }
  .data : { *(.data .data.*) }
  .bss : {
    __bss_start = .;
    *(.bss .bss.*)
    *(COMMON)
    __bss_end = .;
  }
  . = ALIGN(16);
  __stack_end = .;
  . = . + 0x10000;
  __stack_start = .;
  __heap_start = ALIGN(0x1000);
  /* RAM is 256MiB at 0x40000000. */
  __heap_end = 0x50000000;
}
