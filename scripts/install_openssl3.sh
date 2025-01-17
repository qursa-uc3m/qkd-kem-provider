#!/bin/bash

# Default values
INSTALL_DIR="/opt/oqs_openssl3"
SCRIPT_DIR=$(dirname $(readlink -f $0))  # get the full path of the script
DEBUG=0
OPENSSL_BRANCH="openssl-3.4.0"

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
sudo git clone --depth 1 --branch $OPENSSL_BRANCH https://github.com/openssl/openssl.git
cd openssl

sudo ./config --prefix=$(echo $INSTALL_DIR/.local)
sudo make 
sudo make install_sw
cd ..