ENTRY(entry)
SECTIONS {
  . = 0x400000000000;
  .text : { *(.text.entry .ltext.entry) *(.text .text.* .ltext .ltext.*) *(.rodata .rodata.* .lrodata .lrodata.*) }
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
