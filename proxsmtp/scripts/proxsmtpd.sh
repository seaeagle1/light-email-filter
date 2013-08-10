#!/bin/sh

###########################################################################
# CONFIGURATION

# Most configuration options are found in the proxsmtpd.conf file.
# For more info see:
#   man proxsmtpd.conf

# The prefix proxsmtpd was installed to
prefix=/usr/local/

# The location for pid file
piddir=/var/run/

###########################################################################
# SCRIPT

case $1 in
start)
        mkdir -p $piddir
        $prefix/sbin/proxsmtpd -p $piddir/proxsmtpd.pid
        echo -n "proxsmtpd "
        ;;
stop)
        [ -f $piddir/proxsmtpd.pid ] && kill `cat $piddir/proxsmtpd.pid`
        echo -n "proxsmtpd "
        ;;
*)
        echo "usage: proxsmptd.sh {start|stop}" >&2
        ;;
esac
