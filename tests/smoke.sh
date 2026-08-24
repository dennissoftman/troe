# TROE sh deterministic acceptance smoke test.
# This is a shebang-free TROE command file consumed explicitly by the host model;
# it is not intended for execution by a host POSIX shell.
man echo
ls /
cat /etc/motd
echo alpha beta | grep beta | write /tmp/result
cat /tmp/result
mem
halt
