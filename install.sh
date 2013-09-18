#!/bin/bash

cp ksysrqd.ko /lib/modules/$(uname -r)/kernel/drivers/char
depmod -a
