# Verify AWS Nitro enclave PCR0 signature

This is a simple Python script that can be used to [verify the signature of the PCR0](https://github.com/aws/aws-nitro-enclaves-cli/blob/f96a1aeae6162328d90648eb5756a54ac7c5e6d1/docs/image_signing.md) of a Nitro Enclave Image File (EIF) version 4.

The script uses the signing certificate used during the creation of the EIF to verify the signature. It can use a local PEM file or the copy of the certificate that is included in the EIF.

If the signature is valid, the script outputs the signed PCR0 value. The script also computes the hash of the fingerprint of the signing certificate (PCR8).

Both PCR values can be compared to the ones given by `nitro-cli` when building the enclave.

# Prerequisite

The following are assumed to be installed on a Linux system:

- Python3.7
- Docker
- nitro-cli
- Python environnement with libraries listed in `requirements.txt`

# Usage

1. Build a Nitro [EIF with a signature](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html#pcr8) or used the provided `build.sh` script.

1. Run the Python script. Example:

    ```
    python main.py nitro-test.eif --cert_file_path nitro-test-certificate.pem
    ```

