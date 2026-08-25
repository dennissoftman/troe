ENTRY(_start)

PHDRS
{
  text PT_LOAD FLAGS(5);
  rodata PT_LOAD FLAGS(4);
  data PT_LOAD FLAGS(6);
  stack PT_GNU_STACK FLAGS(6);
}

SECTIONS
{
  . = 0x0000400000000000;

  .text : ALIGN(4096)
  {
    KEEP(*(.text._start))
    KEEP(*(.ltext._start))
    *(.text .text.* .ltext .ltext.*)
  } :text

  . = ALIGN(4096);
  .rodata : ALIGN(4096)
  {
    *(.rodata .rodata.* .lrodata .lrodata.*)
  } :rodata

  . = ALIGN(4096);
  .data : ALIGN(4096)
  {
    *(.data .data.* .ldata .ldata.*)
    *(.got .got.*)
  } :data

  .bss : ALIGN(16)
  {
    *(.bss .bss.* .lbss .lbss.*)
    *(COMMON)
  } :data

  /DISCARD/ :
  {
    *(.comment)
    *(.eh_frame .eh_frame.*)
    *(.eh_frame_hdr)
    *(.note .note.*)
  }
}
