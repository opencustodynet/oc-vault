#!/bin/bash

FM_MAX_SIZE=8388608

set -e
set -x

check_fm_size() {
    local fm_file=$1
    fm_size=$(wc -c < $fm_file)
    echo "The FM size is $fm_size bytes"
    if [ "$fm_size" -gt "$FM_MAX_SIZE" ]; then
        echo "The FM size ($fm_size bytes) is greater than max FM size ($FM_MAX_SIZE bytes)."
        exit 1
    fi
}

rm -r output
mkdir output

if [ "$1" = "test-softhsm" ]; then
    (cd vault-proxy && cargo +nightly test $2 --features softhsm -- --nocapture --test-threads 1)
elif [ "$1" = "softhsm" ]; then
    (cd vault-proxy && cargo +nightly rustc --release --features softhsm)
    cp target/release/vault-proxy output/vault-proxy
    echo "output: output/"; ls output/;
elif [ "$1" = "lunahsm" ]; then
    (cd vault-core && cargo +nightly rustc --crate-type staticlib --release --target powerpc-unknown-linux-gnu --features lunahsm)
    (cd vault-core/c && make)
    (cd vault-proxy && cargo +nightly rustc --release --features lunahsm)
    check_fm_size vault-core/c/bin-ppc/vault-core.bin
    cp vault-core/c/bin-ppc/vault-core.bin output/vault-core.bin
    cp target/release/vault-proxy output/vault-proxy
    echo "output: output/"; ls output/;
else
    echo "enter test-softhsm [testname] | softhsm | lunahsm"
fi
