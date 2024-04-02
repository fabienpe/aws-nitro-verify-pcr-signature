# Verify AWS Nitro enclave PCR0 signature

This is a simple Python script that can be used to [verify the value of PCR values and of the the signature of the PCR0](https://github.com/aws/aws-nitro-enclaves-cli/blob/f96a1aeae6162328d90648eb5756a54ac7c5e6d1/docs/image_signing.md) of a Nitro Enclave Image File (EIF) version 4.

The script requires as input the EIF and the base64 encoded attestation of the EIF issued by AWS.

The script also requires the signing certificate used during the creation of the EIF to verify the PCR0 signature: it can use a local PEM file or the copy of the certificate that is included in the EIF.

The script verifies the signature, computes the CRC check of the EIF, and computes the different PCR values of the EIF (which could also be obtained with the nitro-cli tool). The script also compares these computed values with the one provided in the attestation.

## Prerequisite

The following are assumed to be installed on a Linux system:

- Python3.x
- [Docker](https://docs.docker.com/engine/install/)
- [nitro-cli](https://github.com/aws/aws-nitro-enclaves-cli)
- Python environnement with libraries listed in `requirements.txt`

## Usage

1. Build a Nitro [EIF with a signature](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html#pcr8).

1. Get a copy of the attestation of the enclave as URL-safe B64 encoded document.

1. Run the Python script:

    ```
    python main.py nitro-enclave.eif attestation.b64 --cert_file_path nitro-enclave-certificate.pem
    ```

    where 'attestation.b64' contains the url-safe Base64 encoded attestation.
