#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=${BUILD_DIR:-"$root/build"}

cmake -S "$root" -B "$build_dir" \
  -DETSI_004_API="${ETSI_004_API:-OFF}" \
  -DETSI_014_API="${ETSI_014_API:-ON}" \
  -DQKD_KEY_ID_CH="${QKD_KEY_ID_CH:-OFF}" \
  -DQKD_BACKEND="${QKD_BACKEND:-simulated}" \
  -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-RelWithDebInfo}"
cmake --build "$build_dir" --parallel
