FROM ubuntu:22.04

# Install BlueZ and dependencies, including build tools and dbus dev headers
RUN apt-get update && apt-get install -y \
    bluez \
    bluetooth \
    libbluetooth-dev \
    python3 \
    python3-pip \
    python3-venv \
    dbus \
    python3-dbus \
    python3-gi \
    libgirepository1.0-dev \
    build-essential \
    libdbus-1-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Python libs for BLE and crypto (no dbus-python or pygobject via pip)
RUN pip install bleak cryptography pynacl

# Copy your BitChat code (add this file later)
COPY src/bitchat_peer.py /app/bitchat_peer.py

# Entry point script to start services
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

WORKDIR /app
ENTRYPOINT ["/app/entrypoint.sh"]