#!/bin/bash

# Default values
INSTALL_DIR="/opt/oqs_openssl3"
SCRIPT_DIR=$(dirname $(readlink -f $0))  # get the full path of the script
DEBUG=0

# Read flags
while getopts p:d: flag
do
    case "${flag}" in
        p) INSTALL_DIR=${OPTARG};;
        d) DEBUG=${OPTARG};;
    esac
done

# Check if the directory exists and is not empty
if [ -d "$INSTALL_DIR" ] && [ "$(ls -A $INSTALL_DIR)" ]; then
  read -p "The directory $INSTALL_DIR already exists and is not empty. Do you want to remove its contents and continue? (y/n): " confirm
  if [ "$confirm" != "y" ]; then
    exit 1
  fi
  sudo rm -rf $INSTALL_DIR
else
  sudo mkdir -p $INSTALL_DIR
fi


sudo mkdir -p $INSTALL_DIR/.local
cd $INSTALL_DIR

# Build OpenSSL 3.*
echo "BUILDING OPENSSL 3.*...."
sudo git clone https://github.com/openssl/openssl.git
cd openssl

# If debug mode is set, replace the rand_lib.c file
if [ "$DEBUG" -eq 1 ]; then
  echo "Debug mode is set. Replacing rand_lib.c file for logging."
  echo "Taking rand_lib.c from: $SCRIPT_DIR"
  sudo cp "$SCRIPT_DIR/rand_lib.c" ./crypto/rand/rand_lib.c
fi

sudo ./config --prefix=$(echo $INSTALL_DIR/.local)
sudo make 
sudo make install_sw
cd ..

# Create hard link
echo "CREATING HARD LINK...."
sudo ln -f $INSTALL_DIR/.local/bin/openssl /usr/local/bin/oqs_openssl3

# Add to ~/.bashrc
if ! grep -q "export LD_LIBRARY_PATH=\"$INSTALL_DIR/.local/lib64:\$LD_LIBRARY_PATH\"" ~/.bashrc; then
    echo "EXPORTING LD_LIBRARY_PATH to ~/.bashrc ..."
    echo "# CUSTOM OPENSSL3 installation" >> ~/.bashrc
    echo "export LD_LIBRARY_PATH=\"$INSTALL_DIR/.local/lib64:\$LD_LIBRARY_PATH\"" >> ~/.bashrc
fi