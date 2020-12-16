#!/bin/bash
rmmod homa
make clean
make
insmod homa.ko
tail -f /var/log/kern.log