ENTRY(initial_entry)
SECTIONS {
 . = 0x400000000000;
 .text : { KEEP(*(.text.entry.initial)) KEEP(*(.text.entry.worker)) *(.text*) }
 . = ALIGN(4096);
 .tdata : { *(.tdata*) }
 .tbss : { *(.tbss*) }
 /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
