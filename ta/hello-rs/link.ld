/* hello-rs TA. Raw ELF (no RTSG). Kernel load_image reads .rustee.ta_head + TA_* symbols. */
OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(TA_CreateEntryPoint)

EXTERN(TA_CreateEntryPoint)
EXTERN(TA_DestroyEntryPoint)
EXTERN(TA_OpenSessionEntryPoint)
EXTERN(TA_CloseSessionEntryPoint)
EXTERN(TA_InvokeCommandEntryPoint)

PHDRS
{
  text PT_LOAD FLAGS(5);
  data PT_LOAD FLAGS(6);
}

SECTIONS
{
  . = 0x10000;

  .text : {
    *(.text .text.*)
  } :text

  .rodata : {
    *(.rodata .rodata.*)
    *(.srodata .srodata.*)
  } :text

  .rustee.ta_head : ALIGN(8) {
    KEEP(*(.rustee.ta_head))
  } :text

  . = ALIGN(CONSTANT(MAXPAGESIZE));

  .data : {
    *(.data .data.*)
    *(.sdata .sdata.*)
    *(.got .got.*)
  } :data

  .bss : {
    *(.bss .bss.*)
    *(.sbss .sbss.*)
    *(COMMON)
  } :data

  /DISCARD/ : {
    *(.comment)
    *(.note*)
    *(.eh_frame*)
    *(.ARM.exidx*)
  }
}
