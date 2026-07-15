#!/usr/bin/env bash

_qkdkem_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
_qkdkem_build=${BUILD_DIR:-"$_qkdkem_root/build"}

export OPENSSL_MODULES="$_qkdkem_build/lib${OPENSSL_MODULES:+:$OPENSSL_MODULES}"
export LD_LIBRARY_PATH="$_qkdkem_build/qkd-etsi-api${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

export QKD_MASTER_KME_HOSTNAME=${QKD_MASTER_KME_HOSTNAME:-master.example}
export QKD_SLAVE_KME_HOSTNAME=${QKD_SLAVE_KME_HOSTNAME:-slave.example}
export QKD_MASTER_SAE=${QKD_MASTER_SAE:-alice}
export QKD_SLAVE_SAE=${QKD_SLAVE_SAE:-bob}
export QKD_SOURCE_URI=${QKD_SOURCE_URI:-source.example}
export QKD_DEST_URI=${QKD_DEST_URI:-destination.example}

unset _qkdkem_root _qkdkem_build
