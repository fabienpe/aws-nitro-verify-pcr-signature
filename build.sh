#!/bin/bash

parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
cd "$parent_path"

cert_cn="Certificate Name"
cert_c="BE"
cert_st="State"
cert_l="Location"
cert_o="Organisation"
cert_ou="Organisational Unit"

key=nitro-enclave-signing-key.pem
csr=nitro-enclave-enclave-csr.pem
cert=nitro-enclave-certificate.pem

eif=nitro-enclave.eif
enclave_name=nitro-enclave

pcr=enclave-description.json

docker_img=nitro-enclave-example

##########
# Generate private key and signing certificate to sign the Nitro enclave image
# See: https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html#pcr8
##########

rm $key $csr $cert

# Generate a private key
openssl ecparam -name secp384r1 -genkey -out $key

# Generate a certificate signing request (CSR)
openssl req -new -key $key -sha384 -nodes -subj "/CN=${cert_cn}/C=${cert_c}/ST=${cert_st}/L=${cert_l}/O=${cert_o}/OU=${cert_ou}" -out $csr

# Generate a certificate based on the CSR
openssl x509 -req -days 30  -in $csr -out $cert -sha384 -signkey $key

##########
# Create a Nitro enclave
##########

rm $eif
docker build ./ -t $docker_img:latest
nitro-cli build-enclave \
    --docker-uri $docker_img:latest \
    --private-key $key \
    --signing-certificate $cert \
    --output-file $eif

# Get PCR8 value
nitro-cli describe-eif --eif-path $eif > $pcr

