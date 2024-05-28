#!/bin/bash

HSM_SIGNER_SLOT="3"
HSM_ADMIN_SLOT="4"
HSM_PASSWORD="12345678"

# generate FM signer key and certificate
cmu generatekeypair -slot $HSM_SIGNER_SLOT -password $HSM_PASSWORD -labelPrivate fm_signer_prikey -labelPublic fm_signer_public -sign 1 -verify 1 -encrypt 1 -decrypt 1 -mech PKCS -publicExponent 65537 -modulusbits 2048
cmu selfsigncertificate -slot $HSM_SIGNER_SLOT -password $HSM_PASSWORD -label fm_signer_cert -private=T -serialNumber=aabbccdd -CN=fm_signer_cert -startDate=20240101 -endDate=20340101
cmu export -slot $HSM_SIGNER_SLOT -password $HSM_PASSWORD -outputfile ~/fm_signer_cert.cer

# sign FM
mkfm -k SLOTID=$HSM_SIGNER_SLOT/fm_signer_prikey -f ~/vault-core.bin -o ~/vault-core.fm -p $HSM_PASSWORD

# load FM
ctfm i --fm-cert-file=fm_signer_cert.cer --fm-file=~/vault-core.fm -p $HSM_PASSWORD
lunacm -s $HSM_ADMIN_SLOT hsm restart -f
ctfm a -p $HSM_PASSWORD

# test
~/vault_proxy_test --nocapture --test-threads 1
dmesg --time-format ctime