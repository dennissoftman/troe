# ==========================================================================
# postests.sh -- POSIX conformance transcript for custom wc / sed / awk
# Suite version: 3.0 (adds file redirection)
#
# Uses ONLY: command calls, single quotes, pipes, comments, redirection with
# > and <, and the commands echo / printf / cat / wc / sed / awk.
# No variables, no if, no loops, no command substitution, no >>, no 2>,
# no exit-status capture.
#
# Run it in a scratch directory and hand me the whole output.  It leaves a
# number of working files behind (*.out, rt*.txt) -- that is expected.
#
# Tool names are hardcoded as wc / sed / awk.  If your binaries are named
# something else, search-and-replace those three words.
#
# SECTION F builds every fixture with printf, so nothing under test is used
# to build its own inputs.  big.txt is the one exception: 1000 lines is too
# long for a single printf, so awk generates it.  F01 and F02 then print the
# byte count of every fixture -- I check those first, so a fixture that came
# out wrong cannot be mistaken for a tool bug.
# ==========================================================================

echo ===== F00 building fixtures with printf
printf 'hello world\n  foo   bar baz\ntab\there\nlast line\n' > basic.txt
printf 'alpha beta\ngamma' > nonl.txt
printf '' > empty.txt
printf 'a' > onechar.txt
printf '\n   \n\t\n\n' > blank.txt
printf '1 2 3\n4 5 6\n10 20 30\n-1 2.5 3e2\n' > nums.txt
printf 'root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/bin/false\nsync:x:4:65534:sync:/bin:/bin/sync\n:leading:and:trailing:\n' > colon.txt
printf 'aaa\nabc ABC\na.c\nfoo123bar\nx{2}\n[bracket]\nback\\slash\ntab\tsep\na   b\t\tc\n' > re.txt
printf 'apple 3\nbanana 2\napple 5\ncherry 1\nbanana 4\n' > dup.txt
printf 'a1 a2\na3\n\nb1\n\nc1 c2\nc3 c4\n' > para.txt
printf 'one\r\ntwo\r\n' > crlf.txt
printf 'x\ny\n' > two.txt
printf 'line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\n' > lines10.txt
awk 'BEGIN{ for(i=1;i<=1000;i++) print "line " i " of the big file" }' > big.txt
printf '# a comment line\ns/o/0/\ns/l/1/g\n' > p1.sed
printf '1!G\nh\n$!d\n' > tac.sed
printf ':a\nN\n$!ba\ns/\\n/,/g\n' > join.sed
printf ':a\ns/aa/a/\nta\n' > squeeze.sed
printf '1i\\\nINSERTED\n1a\\\nAPPENDED\n3c\\\nCHANGED\n' > aic.sed
printf 's/ /\\\n/\n' > nl.sed
printf 'BEGIN { print "from progfile", x }\n' > p1.awk
printf '{ n++ } END { print "records:", n }\n' > p2.awk

# --------------------------------------------------------------------------
# SECTION wc
# --------------------------------------------------------------------------
echo ===== F01 fixture byte counts, check these first
wc -c basic.txt nonl.txt empty.txt onechar.txt blank.txt nums.txt colon.txt re.txt dup.txt para.txt crlf.txt two.txt lines10.txt big.txt
echo ===== F02 script fixture byte counts
wc -c p1.sed tac.sed join.sed squeeze.sed aic.sed nl.sed p1.awk p2.awk
echo ===== W01 lines only
wc -l basic.txt
echo ===== W02 words only
wc -w basic.txt
echo ===== W03 bytes only
wc -c basic.txt
echo ===== W04 no flags gives lines words bytes
wc basic.txt
echo ===== W05 all three flags spelled out
wc -l -w -c basic.txt
echo ===== W06 flag order must not change column order
wc -c -w -l basic.txt
echo ===== W07 flags bundled
wc -lwc basic.txt
echo ===== W08 bundled subset
wc -wl basic.txt
echo ===== W09 file with no final newline
wc nonl.txt
echo ===== W10 lines counts newlines not lines
wc -l nonl.txt
echo ===== W11 empty file
wc empty.txt
echo ===== W12 one byte no newline
wc onechar.txt
echo ===== W13 blank and whitespace-only lines
wc blank.txt
echo ===== W14 words in a whitespace-only file
wc -w blank.txt
echo ===== W15 CRLF file
wc crlf.txt
echo ===== W16 CR is not a blank in the C locale
wc -w crlf.txt
echo ===== W17 tabs and runs of spaces
wc re.txt
echo ===== W18 chars flag on ASCII equals bytes
wc -m basic.txt
echo ===== W19 1000-line file
wc big.txt
echo ===== W20 lines of a 1000-line file
wc -l big.txt
echo ===== W21 three operands plus a total line
wc basic.txt nonl.txt empty.txt
echo ===== W22 two operands, lines only
wc -l basic.txt lines10.txt
echo ===== W23 same operand twice, total doubles
wc -c two.txt two.txt
echo ===== W24 one operand must NOT print a total
wc -l two.txt
echo ===== W25 double dash ends option processing
wc -- basic.txt
echo ===== W26 stdin from a pipe, bytes
echo abc | wc -c
echo ===== W27 stdin from a pipe, no filename in output
echo abc | wc
echo ===== W28 stdin, words
echo a b c | wc -w
echo ===== W29 stdin, lines, fed by sed
sed '' lines10.txt | wc -l
echo ===== W30 cross-check: awk emits 2 bytes with no newline
awk '{printf "%s", $0}' two.txt | wc -c

# --------------------------------------------------------------------------
# SECTION sed
# --------------------------------------------------------------------------
echo ===== S01 s replaces first occurrence per line
sed 's/o/0/' basic.txt
echo ===== S02 g flag replaces all
sed 's/o/0/g' basic.txt
echo ===== S03 numeric flag replaces only the 2nd match
sed 's/o/0/2' basic.txt
echo ===== S04 numeric flag when fewer matches exist
sed 's/l/L/3' basic.txt
echo ===== S05 ampersand is the whole match
sed 's/[a-z][a-z]*/[&]/' basic.txt
echo ===== S06 escaped ampersand is literal
sed 's/hello/x\&y/' basic.txt
echo ===== S07 backreferences
sed 's/\([a-z]*\) \([a-z]*\)/\2-\1/' basic.txt
echo ===== S08 two groups swapped globally
sed 's/\([a-z]\)\([a-z]\)/\2\1/g' basic.txt
echo ===== S09 alternate delimiter, vertical bar
sed 's|/|:|g' colon.txt
echo ===== S10 escaped delimiter inside the regex
sed 's/\//-/g' colon.txt
echo ===== S11 suppress plus p flag
sed -n 's/o/0/p' basic.txt
echo ===== S12 g and p together
sed -n 's/o/0/gp' basic.txt
echo ===== S13 w flag writes matched lines to a file
sed 's/o/0/w s13.out' basic.txt
echo ===== S14 contents of s13.out
cat s13.out
echo ===== S15 y transliterates
sed 'y/abc/xyz/' basic.txt
echo ===== S16 delete one numbered line
sed '3d' lines10.txt
echo ===== S17 delete a numeric range
sed '2,4d' lines10.txt
echo ===== S18 delete the last line
sed '$d' lines10.txt
echo ===== S19 delete by regex
sed '/line1/d' lines10.txt
echo ===== S20 negated address
sed '/line1/!d' lines10.txt
echo ===== S21 range ending at last line
sed '8,$d' lines10.txt
echo ===== S22 range whose end precedes its start matches one line
sed '5,2d' lines10.txt
echo ===== S23 print a range
sed -n '2,$p' lines10.txt
echo ===== S24 regex range
sed -n '/a1/,/c1/p' para.txt
echo ===== S25 range whose end never matches runs to EOF
sed -n '/line8/,/nomatch/p' lines10.txt
echo ===== S26 equals prints line numbers
sed -n '=' two.txt
echo ===== S27 dollar equals counts lines
sed -n '$=' lines10.txt
echo ===== S28 equals interleaved with auto-print
sed '=' two.txt
echo ===== S29 q quits immediately
sed 'q' lines10.txt
echo ===== S30 q with an address
sed '4q' lines10.txt
echo ===== S31 a i and c from a script file
sed -f aic.sed lines10.txt
echo ===== S32 n prints and loads the next line
sed -n 'n;p' lines10.txt
echo ===== S33 N appends the next line to pattern space
sed 'N;s/\n/+/' lines10.txt
echo ===== S34 N guarded on the last line
sed '$!N;s/\n/+/' two.txt
echo ===== S35 N then P then D
sed 'N;P;D' lines10.txt
echo ===== S36 G appends hold space, double spacing
sed 'G' two.txt
echo ===== S37 x swaps pattern and hold space
sed 'x' two.txt
echo ===== S38 H accumulates, printed at the end
sed -n 'H;${x;s/\n/|/g;p}' two.txt
echo ===== S39 reverse a file with hold space
sed -f tac.sed lines10.txt
echo ===== S40 join all lines using a label and b
sed -f join.sed lines10.txt
echo ===== S41 t branches only after a substitution
sed -f squeeze.sed re.txt
echo ===== S42 braces under an address
sed -n '2,3{s/line/L/;p;}' lines10.txt
echo ===== S43 two -e scripts
sed -e 's/o/0/' -e 's/l/1/g' basic.txt
echo ===== S44 one script, semicolon separated
sed 's/o/0/;s/l/1/g' basic.txt
echo ===== S45 script file with a comment line
sed -f p1.sed basic.txt
echo ===== S46 -e and -f combined
sed -e '1d' -f p1.sed basic.txt
echo ===== S47 caret anchor
sed -n '/^a/p' re.txt
echo ===== S48 dollar anchor
sed -n '/c$/p' re.txt
echo ===== S49 dot matches any character
sed -n '/a.c/p' re.txt
echo ===== S50 escaped dot is literal
sed -n '/a\.c/p' re.txt
echo ===== S51 star is greedy
sed 's/a.*c/X/' re.txt
echo ===== S52 bracket expression
sed -n '/[0-9]/p' re.txt
echo ===== S53 negated bracket expression
sed -n '/^[^a-z]/p' re.txt
echo ===== S54 character class digit
sed 's/[[:digit:]][[:digit:]]*/#/g' re.txt
echo ===== S55 character class space, squeezed
sed 's/[[:space:]][[:space:]]*/ /g' re.txt
echo ===== S56 interval exactly two
sed -n '/a\{2\}/p' re.txt
echo ===== S57 interval one to two
sed 's/a\{1,2\}/A/' re.txt
echo ===== S58 interval two or more
sed -n '/a\{2,\}/p' re.txt
echo ===== S59 unescaped brace is literal in a BRE
sed -n '/x{2}/p' re.txt
echo ===== S60 leading star is literal
sed 's/*/STAR/' re.txt
echo ===== S61 close bracket first in a bracket expression
sed -n '/[][]/p' re.txt
echo ===== S62 empty regex reuses the last one
sed -n '/aaa/{s//AAA/;p;}' re.txt
echo ===== S63 empty-match substitution
sed 's/x*/-/g' two.txt
echo ===== S64 prefix every line
sed 's/^/> /' two.txt
echo ===== S65 suffix every line
sed 's/$/ <-/' two.txt
echo ===== S66 match an empty line
sed 's/^$/EMPTY/' blank.txt
echo ===== S67 replacement containing a newline
sed -f nl.sed basic.txt
echo ===== S68 r reads a file in after line 1
sed '1r two.txt' two.txt
echo ===== S69 w writes every line
sed -n 'w s69.out' two.txt
echo ===== S70 contents of s69.out
cat s69.out
echo ===== S71 missing final newline is preserved, expect 16 bytes
sed 's/alpha/ALPHA/' nonl.txt | wc -c
echo ===== S72 CRLF passes through, expect 10 bytes
sed 's/one/1/' crlf.txt | wc -c
echo ===== S73 strip the CR, expect 8 bytes
sed 's/.$//' crlf.txt | wc -c
echo ===== S74 two operands, dollar is the last line overall
sed -n '$=' two.txt two.txt
echo ===== S75 two operands, print the final line
sed -n '$p' two.txt lines10.txt
echo ===== S76 suppress with no p prints nothing
sed -n 's/x/y/' two.txt
echo ===== S77 empty script is a no-op
sed '' two.txt
echo ===== S78 stdin from a pipe
echo abc | sed -n '1p'
echo ===== S79 p without suppress duplicates lines
sed 'p' two.txt
echo ===== S80 ampersand and backreferences together
sed 's/\([a-z]*\)\(.*\)/[\1]{&}(\2)/' two.txt
echo ===== S81 per-line addressed scripts
sed -e '1s/x/X/' -e '2s/y/Y/' two.txt
echo ===== S82 address with a custom delimiter
sed -n '\%/bin%p' colon.txt

# --------------------------------------------------------------------------
# SECTION awk
# --------------------------------------------------------------------------
echo ===== A01 print with no arguments
awk '{print}' two.txt
echo ===== A02 print dollar zero
awk '{print $0}' basic.txt
echo ===== A03 comma in print uses OFS
awk '{print $1, $3}' nums.txt
echo ===== A04 no comma concatenates
awk '{print $1 $3}' nums.txt
echo ===== A05 NR and NF
awk '{print NR, NF}' basic.txt
echo ===== A06 NF on a blank line is zero
awk '{print NR, NF}' blank.txt
echo ===== A07 last and second-to-last field
awk '{i=NF-1; print $NF, $i}' nums.txt
echo ===== A08 reading past NF is empty and does not change NF
awk '{print NF, "[" $9 "]"}' nums.txt
echo ===== A09 field separator from -F
awk -F: '{print NF, $1, $7}' colon.txt
echo ===== A10 empty leading and trailing fields
awk -F: '$1=="" {print NF, "[" $1 "]", "[" $NF "]"}' colon.txt
echo ===== A11 tab as the field separator
awk -F'\t' '{print NF}' re.txt
echo ===== A12 FS assigned in BEGIN applies to line 1
awk 'BEGIN{FS=":"}{print $1}' colon.txt
echo ===== A13 default FS collapses runs of blanks
awk '{print NF}' re.txt
echo ===== A14 single-space FS as a regex does not collapse
awk 'BEGIN{FS="[ ]"}{print NF}' re.txt
echo ===== A15 assigning a field rebuilds dollar zero with OFS
awk 'BEGIN{OFS="-"}{$1=$1; print}' nums.txt
echo ===== A16 OFS alone does not rebuild dollar zero
awk 'BEGIN{OFS="-"}{print; print $1,$2}' two.txt
echo ===== A17 lowering NF truncates dollar zero
awk '{NF=2; print; print NF}' nums.txt
echo ===== A18 assigning past NF extends NF
awk '{$5="E"; print NF; print}' nums.txt
echo ===== A19 assigning dollar zero re-splits
awk '{$0="p q r"; print NF, $2}' two.txt
echo ===== A20 ORS
awk 'BEGIN{ORS="|"}{print}' two.txt
echo ===== A21 RS as a single character
awk 'BEGIN{RS=":"}{print NR, "[" $0 "]"}' colon.txt
echo ===== A22 paragraph mode, newline is also a separator
awk 'BEGIN{RS=""}{print NR, NF, $1, $NF}' para.txt
echo ===== A23 NR in END
awk 'END{print NR}' lines10.txt
echo ===== A24 FILENAME NR and FNR across two operands
awk '{print FILENAME, NR, FNR}' two.txt two.txt
echo ===== A25 -v assignment is visible in BEGIN
awk -v x=7 'BEGIN{print x+1}'
echo ===== A26 -v value honours escape sequences
awk -v x='a\tb' 'BEGIN{print x}'
echo ===== A27 operand assignments take effect between files
awk '{print v, $0}' v=1 two.txt v=2 two.txt
echo ===== A28 ARGC and ARGV
awk 'BEGIN{print ARGC; for(i=1;i<ARGC;i++) print i, ARGV[i]}' two.txt lines10.txt
echo ===== A29 pattern with no action
awk '/line1/' lines10.txt
echo ===== A30 range pattern
awk '/line3/,/line5/' lines10.txt
echo ===== A31 numeric comparison pattern
awk '$2 > 3 {print $0}' nums.txt
echo ===== A32 string comparison pattern
awk '$1 == "apple" {print $2}' dup.txt
echo ===== A33 match and non-match operators
awk '$0 ~ /a/ {print "Y", NR} $0 !~ /a/ {print "N", NR}' re.txt
echo ===== A34 dynamic regex from a variable
awk -v re='^a' '$0 ~ re {print}' re.txt
echo ===== A35 ternary operator
awk '{print ($1>3 ? "big" : "small")}' nums.txt
echo ===== A36 printf d s c and a literal percent
awk 'BEGIN{printf "%d|%s|%c|%%\n", 42, "str", 65}'
echo ===== A37 printf f e g
awk 'BEGIN{printf "%f|%e|%g\n", 3.14159, 31415.9, 0.000031415}'
echo ===== A38 printf octal and hex
awk 'BEGIN{printf "%o|%x|%X\n", 255, 255, 255}'
echo ===== A39 printf widths and flags
awk 'BEGIN{printf "[%5s][%-5s][%05d][%+d][%.2f]\n", "ab", "ab", 42, 42, 3.14159}'
echo ===== A40 printf c with a string and with a number
awk 'BEGIN{printf "%c%c\n", "xyz", 66}'
echo ===== A41 numeric conversion of strings
awk 'BEGIN{printf "%d|%d|%d|%s\n", "abc", "12abc", " 7 ", (3=="3")}'
echo ===== A42 sprintf
awk 'BEGIN{s=sprintf("%03d/%s", 7, "x"); print s, length(s)}'
echo ===== A43 substr with and without a length
awk 'BEGIN{print substr("hello",2); print substr("hello",2,3)}'
echo ===== A44 substr with out-of-range lengths
awk 'BEGIN{print "[" substr("hello",4,99) "]", "[" substr("hello",9) "]", "[" substr("hello",2,0) "]", "[" substr("hello",2,-1) "]"}'
echo ===== A45 index
awk 'BEGIN{print index("hello","ll"), index("hello","z"), index("hello","hello")}'
echo ===== A46 length in its three forms
awk '{print length, length($0), length($1)}' two.txt
echo ===== A47 length of a number
awk 'BEGIN{print length(1000), length(3.5)}'
echo ===== A48 split with the default separator
awk 'BEGIN{n=split("a  b\tc",arr); print n, arr[1], arr[3]}'
echo ===== A49 split on one character, empty field kept
awk 'BEGIN{n=split("a:b::c",arr,":"); print n, "[" arr[3] "]"}'
echo ===== A50 split on a regex
awk 'BEGIN{n=split("a1b22c",arr,/[0-9]+/); print n, arr[1], arr[2], arr[3]}'
echo ===== A51 sub returns a count and edits dollar zero
awk '{n=sub(/o/,"0"); print n, $0}' basic.txt
echo ===== A52 gsub returns a count
awk '{n=gsub(/o/,"0"); print n, $0}' basic.txt
echo ===== A53 ampersand and escaped ampersand in gsub
awk 'BEGIN{s="ab"; gsub(/a/,"<&>",s); print s; t="ab"; gsub(/a/,"<\\&>",t); print t}'
echo ===== A54 gsub on a field that does not match leaves dollar zero alone
awk '{gsub(/l/,"L",$1); print $1, $0}' basic.txt
echo ===== A55 gsub with an empty-matching regex
awk 'BEGIN{s="abc"; n=gsub(/x*/,"-",s); print n, s}'
echo ===== A56 gsub on dollar zero re-splits the fields
awk '{gsub(/ +/,":"); print NF, $0}' basic.txt
echo ===== A57 match sets RSTART and RLENGTH
awk 'BEGIN{print match("hello world","o w"), RSTART, RLENGTH}'
echo ===== A58 failed match sets zero and minus one
awk 'BEGIN{print match("hello","zz"), RSTART, RLENGTH}'
echo ===== A59 toupper and tolower
awk 'BEGIN{print toupper("aBc1"), tolower("aBc1")}'
echo ===== A60 int truncates toward zero
awk 'BEGIN{print int(3.9), int(-3.9), int("12abc")}'
echo ===== A61 sqrt exp log
awk 'BEGIN{printf "%.6f %.6f %.6f\n", sqrt(2), exp(1), log(10)}'
echo ===== A62 sin cos atan2
awk 'BEGIN{printf "%.6f %.6f %.6f\n", sin(1), cos(1), atan2(1,1)}'
echo ===== A63 division modulus and exponent
awk 'BEGIN{print 7/2, 7%3, 2^10, -7%3}'
echo ===== A64 compound assignment operators
awk 'BEGIN{x=10; x+=5; x-=3; x*=2; x/=4; x%=4; x^=2; print x}'
echo ===== A65 increment and decrement
awk 'BEGIN{i=5; print i++, i, ++i, i--, i, --i}'
echo ===== A66 unary minus versus concatenation
awk 'BEGIN{print 1 " " -1; print 1-1}'
echo ===== A67 OFMT affects print
awk 'BEGIN{print 1/3; OFMT="%.2f"; print 1/3}'
echo ===== A68 CONVFMT affects number to string conversion
awk 'BEGIN{x=1/3; print x ""; CONVFMT="%.2f"; y=1/3; print y ""}'
echo ===== A69 integral values print as integers
awk 'BEGIN{print 2^31, 1e6, 100/4, 3.0}'
echo ===== A70 floating point addition
awk 'BEGIN{print 0.1+0.2, (0.1+0.2==0.3)}'
echo ===== A71 uninitialised variable is both zero and empty
awk 'BEGIN{print u+0, "[" u "]", (u==""), (u==0)}'
echo ===== A72 input fields compare as numbers, quoted strings do not
awk '{print ($1 == 10), ($1 < 9), ($1 "" < "9")}' nums.txt
echo ===== A73 string versus numeric comparison
awk 'BEGIN{print ("10" < "9"), (10 < 9)}'
echo ===== A74 arrays and the in operator
awk '{c[$1]+=$2} END{print c["apple"], ("banana" in c), ("durian" in c)}' dup.txt
echo ===== A75 delete one element
awk 'BEGIN{a[1]=1;a[2]=2; delete a[1]; print (1 in a), (2 in a)}'
echo ===== A76 multi-dimensional subscripts and SUBSEP
awk 'BEGIN{a[1,2]="x"; print a[1,2], ((1,2) in a), length(SUBSEP)}'
echo ===== A77 insertion-ordered output without relying on for-in
awk '{if(!($1 in s)){s[$1]=1;ord[++m]=$1}} END{for(i=1;i<=m;i++) print ord[i]}' dup.txt
echo ===== A78 while loop
awk 'BEGIN{i=0; while(i<3){printf "%d", i; i++}; print ""}'
echo ===== A79 do while loop
awk 'BEGIN{i=0; do{printf "%d", i; i++}while(i<3); print ""}'
echo ===== A80 for loop with continue and break
awk 'BEGIN{for(i=0;i<6;i++){if(i==2)continue; if(i==4)break; printf "%d", i}; print ""}'
echo ===== A81 next skips the remaining rules
awk '/line1$/{print "first"; next} {print "other", NR}' lines10.txt
echo ===== A82 user function with recursion
awk 'function f(n){return n<=1?1:n*f(n-1)} BEGIN{print f(5)}'
echo ===== A83 extra parameters are local
awk 'function g(a, tmp){tmp=a*2; return tmp} BEGIN{tmp=99; print g(3), tmp}'
echo ===== A84 arrays are passed by reference
awk 'function fill(arr){arr["x"]=1} BEGIN{fill(a); print a["x"]}'
echo ===== A85 getline from a file, in a loop
awk 'BEGIN{while((getline l < "two.txt")>0) print "got", l; close("two.txt")}'
echo ===== A86 getline from a missing file returns minus one
awk 'BEGIN{print (getline l < "no_such_file.txt")}'
echo ===== A87 plain getline advances NR and dollar zero
awk 'NR==1{getline; print "after getline NR=" NR, $0}' lines10.txt
echo ===== A88 getline into a variable leaves dollar zero alone
awk 'NR==1{getline v; print "v=" v, "dollar0=" $0, "NR=" NR}' lines10.txt
echo ===== A89 print to a file, then read it back
awk 'BEGIN{print "a" > "a89.out"; print "b" > "a89.out"; close("a89.out"); while((getline l < "a89.out")>0) print "read", l}'
echo ===== A90 printf to a file
awk 'BEGIN{printf "x=%d\n", 5 > "a90.out"}'
echo ===== A91 contents of a90.out
cat a90.out
echo ===== A92 exit in a main rule still runs END
awk 'NR==2{exit 0} {print NR} END{print "END ran, NR=" NR}' lines10.txt
echo ===== A93 program from a file
awk -f p1.awk two.txt
echo ===== A94 program from a file plus -v
awk -v x=9 -f p1.awk two.txt
echo ===== A95 two program files
awk -f p1.awk -f p2.awk two.txt
echo ===== A96 string escape sequences
awk 'BEGIN{print "a\tb", "c\nd", "e\\f", "g\"h", "\061\062"}'
echo ===== A97 stdin from a pipe
echo 1 | awk '{print $1+1}'
echo ===== A98 empty program prints nothing
awk '' two.txt
echo ===== A99 numeric and string concatenation
awk 'BEGIN{print 1 2, "a" 1+1}'
echo ===== A100 assigning the last field
awk '{$NF="LAST"; print}' basic.txt
echo ===== A101 5000-character string
awk 'BEGIN{s=""; for(i=0;i<5000;i++) s=s "x"; print length(s)}'

# --------------------------------------------------------------------------
# SECTION stdin -- redirection and cat as input sources
# --------------------------------------------------------------------------
echo ===== X01 wc reading stdin must not print a filename
wc < basic.txt
echo ===== X02 wc -l from stdin, file has no final newline
wc -l < nonl.txt
echo ===== X03 wc -c from stdin, one byte no newline
wc -c < onechar.txt
echo ===== X04 wc from stdin, empty file
wc < empty.txt
echo ===== X05 wc -m from stdin
wc -m < basic.txt
echo ===== X06 wc -w from stdin, whitespace-only file
wc -w < blank.txt
echo ===== X07 wc via cat, must match X01
cat basic.txt | wc
echo ===== X08 wc via cat of two files, newlines add up
cat basic.txt nonl.txt | wc -l
echo ===== X09 wc via cat of an empty file
cat empty.txt | wc
echo ===== X10 sed reading stdin
sed 's/o/0/' < basic.txt
echo ===== X11 sed counting lines from stdin
sed -n '$=' < lines10.txt
echo ===== X12 sed on empty stdin prints nothing
sed 'p' < empty.txt
echo ===== X13 sed script file applied to stdin
sed -f tac.sed < lines10.txt
echo ===== X14 sed reading a pipe from cat
cat two.txt | sed 'G'
echo ===== X15 awk reading stdin
awk '{print NR, NF}' < basic.txt
echo ===== X16 awk counting 1000 records from stdin
awk 'END{print NR}' < big.txt
echo ===== X17 awk on empty stdin still runs END
awk 'END{print NR}' < empty.txt
echo ===== X18 awk paragraph mode from stdin
awk 'BEGIN{RS=""}{print NR, NF}' < para.txt
echo ===== X19 awk summing a piped file
cat nums.txt | awk '{s+=$1} END{print s}'
echo ===== X20 INFO unspecified, awk FILENAME while reading stdin
awk 'NR==1{print "[" FILENAME "]"}' < two.txt

# --------------------------------------------------------------------------
# SECTION round trips -- each test writes a file, then inspects it.
# --------------------------------------------------------------------------
echo ===== R01 sed output to a file, then count its bytes
sed 's/o/0/' basic.txt > rt01.txt
wc -c rt01.txt
echo ===== R02 missing final newline survives a redirect, expect 16
sed '' nonl.txt > rt02.txt
wc -c rt02.txt
echo ===== R03 awk always terminates output with ORS, expect 17
awk '{print}' nonl.txt > rt03.txt
wc -c rt03.txt
echo ===== R04 awk printf writes no trailing newline, expect 2
awk '{printf "%s", $0}' two.txt > rt04.txt
wc -c rt04.txt
echo ===== R05 stripping the CR, expect 8
sed 's/.$//' crlf.txt > rt05.txt
wc -c rt05.txt
echo ===== R06 suppressed sed writes a genuinely empty file, expect 0
sed -n 's/x/y/' two.txt > rt06.txt
wc -c rt06.txt
echo ===== R07 reversing twice restores the original order
sed -f tac.sed lines10.txt > rt07.txt
sed -f tac.sed rt07.txt
echo ===== R08 joined file byte count
sed -f join.sed lines10.txt > rt08.txt
wc -c rt08.txt
echo ===== R09 equals output and pattern space keep their order in a file
sed '=' two.txt > rt09.txt
cat rt09.txt
echo ===== R10 BEGIN main and END output keep their order in a file
awk 'BEGIN{print "begin"} {print} END{print "end"}' two.txt > rt10.txt
cat rt10.txt
echo ===== R11 file written by awk, read back by sed
awk 'BEGIN{for(i=1;i<=3;i++) print i}' > rt11.txt
sed -n '$=' rt11.txt
echo ===== R12 file written by sed, read back by awk
sed -f tac.sed two.txt > rt12.txt
awk '{print NR, $0}' rt12.txt
echo ===== R13 sed w file and stdout are independent, stdout part
sed 'w rt13w.txt' two.txt > rt13.txt
cat rt13.txt
echo ===== R14 the w file written during R13
cat rt13w.txt
wc -c rt13w.txt
echo ===== R15 awk internal redirection and stdout are independent, stdout part
awk '{print "so" NR; print "fo" NR > "rt15f.txt"}' two.txt > rt15.txt
cat rt15.txt
echo ===== R16 the file awk wrote internally during R15
cat rt15f.txt
wc -c rt15f.txt
echo ===== R17 two tools chained through a temporary file
sed 's/ /,/g' basic.txt > rt17a.txt
awk -F, '{print NF}' rt17a.txt
echo ===== R18 output fed back into the same program is stable
awk '{$1=$1; print}' nums.txt > rt18.txt
awk '{$1=$1; print}' rt18.txt

# --------------------------------------------------------------------------
# SECTION optional -- these two need awk to be able to run a child process.
# If your awk has no popen yet, their failure is expected, not a bug.
# --------------------------------------------------------------------------
echo ===== P01 OPTIONAL, needs subprocess support, pipe a command into getline
awk 'BEGIN{"echo piped" | getline v; print v; close("echo piped")}'
echo ===== P02 OPTIONAL, needs subprocess support, pipe output to sort
awk 'BEGIN{print "b" | "sort"; print "a" | "sort"; close("sort")}'

echo ===== END of transcript