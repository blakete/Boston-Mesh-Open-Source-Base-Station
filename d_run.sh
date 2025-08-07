#!/bin/bash
# docker run --privileged --net=host --device=/dev/bus/usb/001/003 \  # Adjust to your dongle's path (use lsusb to find)
#     -v /dev/bus/usb:/dev/bus/usb \  # Mount USB bus
#     -it bitchat-linux
docker run --privileged --net=host \
    -v /dev/bus/usb:/dev/bus/usb \
    -it bitchat-linux