#!/bin/bash

set -x
MODULE="--module /usr/lib/softhsm/libsofthsm2.so"
HSM_PASSWORD="12345678"
HSM_SLOT_LABEL="opencustody_slot"
CONNECTION="$MODULE --token-label $HSM_SLOT_LABEL --login --login-type user --pin $HSM_PASSWORD"
pkcs11-tool $MODULE --init-token --label $HSM_SLOT_LABEL --so-pin $HSM_PASSWORD
pkcs11-tool $MODULE --init-pin --label $HSM_SLOT_LABEL --login --login-type so --so-pin $HSM_PASSWORD --pin $HSM_PASSWORD
set +x
