#!/bin/bash

set -e

check_fm_size() {
    FM_MAX_SIZE=8388608
    local fm_file=$1
    fm_size=$(wc -c < $fm_file)
    echo "The FM size is $fm_size bytes"
    if [ "$fm_size" -gt "$FM_MAX_SIZE" ]; then
        echo "The FM size ($fm_size bytes) is greater than max FM size ($FM_MAX_SIZE bytes)."
        exit 1
    fi
}

cargo rustc -p vault-core --crate-type staticlib --release --target powerpc-unknown-linux-gnu --features lunahsm_fm
make -C vault-core/fm
check_fm_size target/powerpc-unknown-linux-gnu/release/vault-core.bin