#!/bin/bash
rmmod homa
make clean
make
insmod homa.ko
make clean
tail -f /var/log/kern.log

