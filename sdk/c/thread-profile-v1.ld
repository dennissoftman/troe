/* Compiler qualification only; native ABI 1.4 admission is disabled.
 * Keep target-specific trap padding inside the executable section's file
 * extent. Unattributed nonzero bytes remain invalid converter input.
 */
SECTIONS
{
  .text : { *(.text .text.*) . = ALIGN(4096); }
}
INSERT AFTER .dynstr;
