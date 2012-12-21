#!/bin/bash
make install
make wlunload
modprobe ath9k
ifconfig wlan0 up
iw dev wlan0 set channel 6
iw dev wlan0 set power_save off
