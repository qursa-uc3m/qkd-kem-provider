#!/bin/bash

# Default values
INSTALL_DIR="/opt/oqs_openssl3"
LIBOQS_BRANCH="0.12.0"
OQS_PROVIDER_BRANCH="0.8.0"
PROVIDERS_DIR="/usr/local/lib/ossl-modules/"

# Read flags
while getopts p: flag
do
    case "${flag}" in
        p) INSTALL_DIR=${OPTARG};;
    esac
done

# Check if oqs-provider directory exists
if [ -d "$INSTALL_DIR/oqs-provider" ] && [ "$(ls -A $INSTALL_DIR/oqs-provider)" ]; then
    read -p "The directory $INSTALL_DIR/oqs-provider already exists. Remove it and continue? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        exit 1
    fi
    sudo rm -rf "$INSTALL_DIR/oqs-provider"
fi

# Create directory if it doesn't exist
sudo mkdir -p "$INSTALL_DIR"
sudo mkdir -p "$PROVIDERS_DIR"
cd "$INSTALL_DIR"

# Clone and build oqs-provider
echo "Cloning oqs-provider version $OQS_PROVIDER_BRANCH..."
sudo git clone --depth 1 --branch "$OQS_PROVIDER_BRANCH" https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider

# Build with specific liboqs version
echo "Building oqs-provider with liboqs $LIBOQS_BRANCH..."
export LIBOQS_BRANCH="$LIBOQS_BRANCH"
sudo ./scripts/fullbuild.sh -F

# Copy provider to common directory
sudo cp _build/lib/oqsprovider.so "$PROVIDERS_DIR/"

echo "oqs-provider installation completed in $INSTALL_DIR/oqs-provider"
echo "Provider copied to $PROVIDERS_DIR"
echo "Add to your environment:"
echo "export OPENSSL_MODULES=\"$PROVIDERS_DIR:\$OPENSSL_MODULES\""