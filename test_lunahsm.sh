#!/bin/bash

HSM_SIGNER_SLOT="3"
HSM_ADMIN_SLOT="4"
HSM_PASSWORD="12345678"

# generate FM signer key and certificate
cmu generatekeypair -slot $HSM_SIGNER_SLOT -password $HSM_PASSWORD -labelPrivate fm_signer_prikey -labelPublic fm_signer_public -sign 1 -verify 1 -encrypt 1 -decrypt 1 -mech PKCS -publicExponent 65537 -modulusbits 2048
cmu selfsigncertificate -slot $HSM_SIGNER_SLOT -password $HSM_PASSWORD -label fmsignerCert -private=T -serialNumber=a1b2c3d4 -CN=fmsignerCert -startDate=20230101 -endDate=20330101
cmu export -slot $HSM_SIGNER_SLOT -password $HSM_PASSWORD -outputfile ~/fmsignerCert.cer

mkfm -k SLOTID=$HSM_SIGNER_SLOT/fm_signer_prikey -f output/kvhsm.bin -o output/kvhsm.fm -p $HSM_PASSWORD
ctfm i --fm-cert-file=fmsignerCert.cer --fm-file=output/kvhsm.fm -p $HSM_PASSWORD
lunacm -s $HSM_ADMIN_SLOT hsm restart -f
ctfm a -p $HSM_PASSWORD
dmesg --time-format ctime

# test
output/$TEST_BIN_NAME $2 --nocapture --test-threads 1