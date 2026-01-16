#!/bin/sh

binary="$1"

openocd -f ./openocd/run.cfg -c "program $binary verify reset exit"
