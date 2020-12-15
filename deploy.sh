#!/bin/bash
rmmod homa
make clean
make
insmod homa.ko