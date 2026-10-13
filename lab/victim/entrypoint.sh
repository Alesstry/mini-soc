#!/bin/sh
set -e
rsyslogd              # se daemoniza y crea /dev/log
sleep 1
exec /usr/sbin/sshd -D   # SIN -e: queremos que loguee a syslog, no a stderr
