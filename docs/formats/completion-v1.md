# CMPL v1 completion artifact

CMPL v1 is the canonical package-owned declarative shell-completion artifact.
Its exact bytes are embedded at the end of a KEX package and bound to one
installed command name. It is never an independently installed `/bin` sidecar
and it grants no application authority.

The artifact is canonical UTF-8 text, is at most 16 KiB, and ends in exactly one
newline. Fields are separated by tabs. The first record is:

```text
CMPL<TAB>1<TAB>command
```

It is followed by zero to 64 ordered rule records:

```text
R<TAB>minimum<TAB>maximum<TAB>prefix<TAB>resolver[<TAB>condition...]
```

Argument positions are one-based after the command word. `maximum` may be `*`
for every subsequent position. `prefix` is `*` or `^TEXT`. The first matching
rule selects one trusted semantic resolver:

- `values:VALUE[,VALUE...]`, with unique bytewise-sorted bare values;
- `path:file`, `path:directory`, or `path:any`;
- `command`;
- `address:FAMILY:PORT`, where family is `ipv4`, `ipv6`, `ip`, `hostname`, or
  `any`, and port is `forbidden`, `optional`, or `required`;
- `integer:RADIX:MINIMUM:MAXIMUM`, where radix is `binary`, `octal`, `decimal`,
  or `hexadecimal`, and either bound may be `*`;
- `job`, `service`, or `volume`.

Conditions are `eq:INDEX:TEXT`, `ne:INDEX:TEXT`, `starts:INDEX:TEXT`, or
`not-starts:INDEX:TEXT`, with zero-based indexes into already parsed arguments.
Each rule has at most eight conditions. Text operands are nonempty printable
ASCII bare-word components of at most 512 bytes. Whitespace, control bytes,
tabs, `%`, `,`, and `:` are rejected so the current format never implies a
quoting or escaping dialect. A later format version may add explicit quoted
text without weakening v1 canonicality.

An artifact containing only its header is an explicit declaration that the
application has no useful argument candidates. Package building validates the
artifact and requires its command to match the installed filename. Activation
reads only the fixed KEX package header and bounded CMPL range, validates the
same identity again, and publishes a read-only revision-bound registry. Tab
does not execute the application.

Resolver names are a closed semantic vocabulary; values are not a closed set.
For example, `path:file` traverses the current namespace, `job` visits the
session's current jobs, and `integer` validates values against typed bounds.
The shell owns parsing, sorting, deduplication, replacement ranges, insertion,
quoting policy, and all count and byte budgets.
