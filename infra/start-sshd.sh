#!/bin/bash
# start sshd and rsyslog
service rsyslog start >/dev/null 2>&1 || true
mkdir -p /var/run/sshd
ssh-keygen -A >/dev/null 2>&1 || true
exec /usr/sbin/sshd -D -e
