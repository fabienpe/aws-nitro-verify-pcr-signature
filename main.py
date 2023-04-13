"""
This is a simple Python script that can be used to of a Nitro Enclave Image File (EIF) version 4.

Author: https://github.com/fabienpe/
"""

from binascii import hexlify
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pycose.keys.ec2 import EC2Key as EC2
from pycose.keys.curves import P384
from pycose.messages import Sign1Message

import cbor2
import click

@click.command()
@click.argument('eif_file_path')
@click.option('--cert_file_path', type=str,
              help='PEM signing certificate.')
def main(eif_file_path, cert_file_path):
    signature_section = None

    try:
        with open(eif_file_path, 'rb') as eif_file:
            # Read header without CRC
            header_buf = eif_file.read(544)
            assert header_buf[0:4] == b'.eif', "Unexpected file type"

            # Read CRC
            eif_file.read(4)  # Read 32 bit CRC

            # Read magic numbers (4 u8)
            magic = [0] * 4
            for i in range(0, 4):
                magic[i] = int.from_bytes(header_buf[i:i+1], 'big')

            # Read version (u16)
            version = int.from_bytes(header_buf[4:6], 'big')
            print(f'Version={version}')
            assert version == 4, "Wrong EIF format version"

            # Read flags (u16)
            int.from_bytes(header_buf[6:8], 'big')

            # Read default_mem (u64)
            default_mem = int.from_bytes(header_buf[8:16], 'big')
            print(f'Default memory={default_mem}')

            # Read default_cpus (u64)
            default_cpus = int.from_bytes(header_buf[16:24], 'big')
            print(f'Default CPUs={default_cpus}')

            # Read reserved (u16)
            int.from_bytes(header_buf[24:26], 'big')

            # Read num_sections (u16)
            num_sections = int.from_bytes(header_buf[26:28], 'big')
            print(f'Number of sections={num_sections}')

            max_num_sections = 32

            # Read section_offsets (list of u64)
            section_offsets = [0] * max_num_sections
            for i in range(0, max_num_sections):
                section_offsets[i] = int.from_bytes(header_buf[28+i*8:28+(i+1)*8], 'big')
            print(f'Section offsets={section_offsets}')

            # Read section_sizes (list of u64)
            section_sizes = [0] * max_num_sections
            for i in range(0, max_num_sections):
                section_sizes[i] = int.from_bytes(header_buf[284+i*8:284+(i+1)*8], 'big')
            print(f'Section sizes={section_sizes}')

            # Read signature section (type 4)
            # See aws-nitro-enclave-image-format/src/def/mod.rs for list of sections
            eif_file.seek(section_offsets[5])
            section_header = eif_file.read(12)

            # Read section type
            section_type = int.from_bytes(section_header[0:2], 'big')
            assert section_type == 4, "Wrong section type"
            print(f'Section type={section_type}')

            # Read section flag (u16)
            section_flags = int.from_bytes(section_header[2:4], 'big')
            print(f'Section flags={section_flags}')

            # Read section size (u64)
            section_size = int.from_bytes(section_header[4:12], 'big')
            print(f'Section size={section_size}')

            # Read signature section content
            signature_section = eif_file.read(section_size)
    except IOError:
        print(f'ERROR: Could not find or read the enclave image file ({eif_file_path})')
        exit(1)

    # Decode signature section
    des_sign = cbor2.loads(signature_section)
    certificate = des_sign[0]['signing_certificate']
    certificate = bytes(certificate)

    # AWS Nitro library does not add tag. See generate_pcr_signature in EIfBuilder class
    # so add tag "18" (COSE Sign1) manually
    signature = des_sign[0]['signature']
    signature = bytes([6 << 5 | 18] + signature)

    # Load signing certificate from local PEM file or from EIF
    if cert_file_path:
        print(f'Using signing certificate provided in {cert_file_path}.')
        try:
            with open(cert_file_path, 'rb') as certificate_file:
                cert = x509.load_pem_x509_certificate(certificate_file.read())
        except IOError:
            print(f'ERROR: Could not read signing certificate file {cert_file_path}')
            exit(1)
    else:
        print("Using signing certificate provided in EIF.")
        cert = x509.load_pem_x509_certificate(certificate)

    # Generate a SHA384 hash of the DER encoded certificate
    cert_hash = cert.fingerprint(hashes.SHA384())

    # Hash the previous hash with a zeroed string
    hasher = hashes.Hash(hashes.SHA384())
    hash_size = hashes.SHA384.digest_size
    hasher.update(b'\0' * hash_size)
    hasher.update(cert_hash)
    print(f'PCR8: {hasher.finalize().hex()}')

    # Get public key from certificate
    cert_public_numbers = cert.public_key().public_numbers()
    key = EC2(x = cert_public_numbers.x.to_bytes(48, 'big'),
              y = cert_public_numbers.y.to_bytes(48, 'big'),
              crv = P384)

    # Verify COSE Sign1 signature
    decoded = Sign1Message.decode(signature)
    decoded.key = key
    if decoded.verify_signature():
        pcr=cbor2.loads(decoded.payload)
        print(f'Valid PCR{pcr["register_index"]} signature')
        print(f'PCR{pcr["register_index"]}: {hexlify(bytes(pcr["register_value"])).decode()}')
    else:
        print('PCR signature not valid.')

if __name__ == '__main__':
    main()  # pylint: disable=no-value-for-parameter.
