#!/bin/bash
service dbus start
/usr/lib/bluetooth/bluetoothd -n &  # Start BlueZ daemon
sleep 2  # Wait for init
hciconfig hci0 up  # Enable adapter
python3 bitchat_peer.py