# Stage 0 deterministic acceptance smoke test
help echo
ls /
cat /etc/motd
echo alpha beta | grep beta | write /tmp/result
cat /tmp/result
mem
halt

