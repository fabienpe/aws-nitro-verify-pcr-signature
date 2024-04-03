"""
This is a simple Python script that can be used to verify CRC, PCR0, PCR1,
PCR2 and PCR8 values of a Nitro Enclave Image File (EIF) version 4.

Author: https://github.com/fabienpe/
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from enum import Enum
from OpenSSL import crypto as sslcrypto
from pycose.keys.ec2 import EC2Key as EC2
from pycose.keys.curves import P384
from pycose.messages import Sign1Message
from urllib.parse import urlparse
from zlib import crc32

import base64
import cbor2
import click
import os
import requests
import tempfile
import zipfile


AWS_NITRO_CERT='https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip'


class EifSectionType(Enum):
    INVALID = 0
    KERNEL = 1
    CMD_LINE = 2
    RAM_DISK = 3
    SIGNATURE = 4
    METADATA = 5


class SHA384Hasher:
    """The PCR values are SH384 of zeroed block and the SHA384 of the content
    """
    def __init__(self):
        self.hasher = hashes.Hash(hashes.SHA384())
        self.hash_size = hashes.SHA384.digest_size

    def update(self, buffer):
        self.hasher.update(buffer)

    def finalize(self):
        # Has the value of the hash computed so far with a block of 0
        hash = self.hasher.finalize()
        
        hasher = hashes.Hash(hashes.SHA384())
        hasher.update(b'\0' * self.hash_size)
        hasher.update(hash)
        return hasher.finalize()


def verify_certificate(attestation_doc_obj: dict, cert: sslcrypto.X509):
    """Verify the signing certificate of an attestation document.

    Args:
        attestation_doc_obj (dict): Attestation document array
        cert (sslcrypto.X509): Certificate of the key used to sign the attestation
    """
    # Get the AWS root certificate
    aws_root_cert_pem = get_aws_root_cert()

    # Create an X509Store object for the CA bundles
    store = sslcrypto.X509Store()

    # This first CA in the CA bundle should be the AWS root certificate
    # Create the CA cert object from PEM string, and store into X509Store
    aws_root_cert = sslcrypto.load_certificate(sslcrypto.FILETYPE_PEM, aws_root_cert_pem)
    store.add_cert(aws_root_cert)

    # Get the interim and target certificate from CA bundle and add them to the X509Store
    # Except the first certificate, which is the root certificate and which has been
    # replaced by the known one (above)
    for intermediary_cert_binary in attestation_doc_obj['cabundle'][1:]:
        intermediary_cert = sslcrypto.load_certificate(sslcrypto.FILETYPE_ASN1,
                                                       intermediary_cert_binary)
        store.add_cert(intermediary_cert)

    # Get the X509Store context
    store_ctx = sslcrypto.X509StoreContext(store, cert)

    # Validate the certificate
    # If the cert is invalid, it will raise exception
    try:
        store_ctx.verify_certificate()
    except sslcrypto.X509StoreContextError as error:
        print(f'Certificate not valid. {error}')
        return

    print('Valid AWS signing certificate')


def verify_signature(cose_sign_obj: list, cert: x509):
    """Verify the the signature of the attestation document
    See:
    https://www.rfc-editor.org/rfc/rfc8152
    https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md
    https://pycose.readthedocs.io/en/latest/pycose/messages/sign1message.html
    https://github.com/awslabs/aws-nitro-enclaves-cose/blob/main/src/sign.rs

    Args:
        cose_sign_obj (list): COSE Sign1 object
        cert (X509): Certificate of the signing key

    Raises:
        Exception: Generic exception if the signature is not correct
    """
    # Get the key parameters from the certificate's public key
    cert_public_numbers = cert.public_key().public_numbers()

    # Create the EC2 key from public key parameters
    key = EC2(x = cert_public_numbers.x.to_bytes(48, 'big'),
            y = cert_public_numbers.y.to_bytes(48, 'big'),
            crv = P384)

    # Construct the Sign1 message
    sign1_msg = Sign1Message.from_cose_obj(cose_sign_obj, True)
    sign1_msg.key = key

    # Verify the signature using the EC2 key
    if not sign1_msg.verify_signature():  # pylint:  disable=no-member
        raise Exception('Wrong signature')

    print('Valid signature on attestation document')


def get_aws_root_cert() -> str:
    """Get the PEM content of the AWS Nitro Enclave root certificate

    Returns:
        str: Root certificate PEM content
    """
    url_elements = urlparse(AWS_NITRO_CERT)
    zip_filename = os.path.basename(url_elements.path)

    # Create a temporary directory
    with tempfile.TemporaryDirectory() as tmp_dir_name:

        # Download the ZIP file containing the certificate and save to file
        with open (os.path.join(tmp_dir_name, zip_filename), "wb") as file:
            file.write(requests.get(AWS_NITRO_CERT, timeout=3).content)

        # Decompress the ZIP file
        with zipfile.ZipFile(os.path.join(tmp_dir_name, zip_filename), "r") as zip_ref:
            zip_ref.extractall(tmp_dir_name)

        # Load the content of the certificate from file
        with open(os.path.join(tmp_dir_name, 'root.pem'), mode = 'r', encoding= 'ascii') as file:
            aws_root_cert_pem = file.read()

    print(aws_root_cert_pem)

    return aws_root_cert_pem


def check_attestation_document(attestation_doc_obj: dict,
                               public_key: bool = False,
                               user_data: bool = False,
                               nonce: bool = False):
    """Verify the fields of an Attestation Document. Optional fields are checked if
    the corresponding input parameter is set to True.
    See: https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md

    Args:
        attestation_doc_obj (dict): Attestation document array.
        public_key (bool, optional): If True, check the public key field. Defaults to False.
        user_data (bool, optional): If True, check the user_data field. Defaults to False.
        nonce (bool, optional): If True, check the nonce field. Defaults to False.
    """
    mandatory_fields = ["module_id", "digest", "timestamp", "pcrs", "certificate", "cabundle"]
    authorised_pcr_lengths = [32, 48, 64]
    authorised_digests = ['SHA384']

    for field in mandatory_fields:
        assert field in attestation_doc_obj.keys(), f'Missing field: {field}'

        assert isinstance(attestation_doc_obj['module_id'], str) \
           and len(attestation_doc_obj['module_id']) != 0, \
           'Empty module ID'

    assert isinstance(attestation_doc_obj['digest'], str) \
           and attestation_doc_obj['digest'] in authorised_digests, \
           'Wrong digest'

    assert isinstance(attestation_doc_obj['timestamp'], int) \
           and attestation_doc_obj['timestamp'] > 0, \
           'Timestamp must be greater than 0'

    assert isinstance(attestation_doc_obj['pcrs'], dict) \
           and len(attestation_doc_obj['pcrs']) >= 1 \
           and len(attestation_doc_obj['pcrs']) <= 32, \
           'There should be at least one and at most 32 PCR fields'

    for index, value in attestation_doc_obj['pcrs'].items():
        assert isinstance(index, int), \
            'PCR indices should be integers'
        assert isinstance(value, bytes), \
            'PCR content must be a byte string'
        assert len(value) in authorised_pcr_lengths, \
            f'Length of PCR can be one of these values: {authorised_pcr_lengths}'

    assert isinstance(attestation_doc_obj['cabundle'], list), \
        'CA Bundle should be a list'
    assert len(attestation_doc_obj['cabundle']) > 0, \
        'CA Bundle should not be empty'

    for element in attestation_doc_obj['cabundle']:
        assert isinstance(element, bytes), \
            'CA bundle entry must have byte string type'
        assert len(element) >= 1 and len(element) <= 1024, \
            'CA bundle entry must have length between 1 and 1024'

    if public_key:
        assert 'public_key' in attestation_doc_obj.keys(), \
            'Public key not present in attestation document'
        assert isinstance(attestation_doc_obj['public_key'], bytes) \
               and len(attestation_doc_obj['public_key']) >= 1 \
               and len(attestation_doc_obj['public_key']) <= 1024, \
               'Public key must be a string between 1 and 1024 bytes'

    if user_data:
        assert 'user_data' in attestation_doc_obj.keys(), \
            'User data key not present in attestation document'
        assert isinstance(attestation_doc_obj['user_data'], bytes) \
               and len(attestation_doc_obj['user_data']) >= 0 \
               and len(attestation_doc_obj['user_data']) <= 512, \
               'User data must be a string between 0 and 512 bytes'

    if nonce:
        assert 'nonce' in attestation_doc_obj.keys(), \
            'Nonce not present in attestation document'
        assert isinstance(attestation_doc_obj['nonce'], bytes) \
               and len(attestation_doc_obj['nonce']) >= 0 \
               and len(attestation_doc_obj['nonce']) <= 512, \
               'Nonce must be a string between 0 and 512 bytes'

    print('Valid attestation')



@click.command()
@click.argument('eif_file_path')
@click.option('--attestation_file_path', type=str,
              help="B64 encoded of the attestation of the EIF.")
@click.option('--cert_file_path', type=str,
              help='PEM signing certificate.')
def main(eif_file_path, cert_file_path, attestation_file_path):
    
    eif_crc = 0
    computed_eif_crc = 0
    cert = None
    signature = None
    attestation_doc = None

    image_hasher = SHA384Hasher()
    bootstrap_hasher = SHA384Hasher()
    app_hasher = SHA384Hasher()
    cert_hasher = SHA384Hasher()

    digests = {}  # For storing expected and actual CRC and PCR values

    try:
        with open(eif_file_path, 'rb') as eif_file:

            # Read header without CRC
            header_buf = eif_file.read(544)
            assert header_buf[0:4] == b'.eif', "Unexpected file type"
            computed_eif_crc = crc32(header_buf, computed_eif_crc)         

            # Read components of header

            # Read magic numbers (4 u8) used to identify the EIF file format
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

            # Read section_offsets (list of u64)
            section_offsets = [0] * num_sections
            for i in range(0, num_sections):
                section_offsets[i] = int.from_bytes(header_buf[28+i*8:28+(i+1)*8], 'big')
            print(f'Section offsets={section_offsets}')

            # Read section_sizes (list of u64)
            section_sizes = [0] * num_sections
            for i in range(0, num_sections):
                section_sizes[i] = int.from_bytes(header_buf[284+i*8:284+(i+1)*8], 'big')
            print(f'Section sizes={section_sizes}')

            # Read CRC
            eif_crc = int.from_bytes(eif_file.read(4), 'big') # Read 32 bit CRC
            assert eif_file.tell() == 548

            # Read other sections of the EIF and compute PCR values
            ram_disk_id = 0
            while True:               
                # print(f'Section - Location {eif_file.tell()}')
                
                # Read section header
                section_header = eif_file.read(12)
                if not section_header:
                    break

                # Update CRC
                computed_eif_crc = crc32(section_header, computed_eif_crc)
                
                # Read section type
                section_type = EifSectionType(int.from_bytes(section_header[0:2], 'big'))
                print(f'    type={section_type}')

                # Read section flag (u16)
                section_flags = int.from_bytes(section_header[2:4], 'big')
                print(f'    flags={section_flags}')

                # Read section size (u64)
                section_size = int.from_bytes(section_header[4:12], 'big')
                # assert section_size == section_sizes[i]
                print(f'    size={section_size}')

                # Read section from file
                section_buffer = eif_file.read(section_size)
                if not section_buffer:
                    print('Unexpected error while reading section')
                    break

                # Update RCR value
                computed_eif_crc = crc32(section_buffer, computed_eif_crc)
                        
                if section_type == EifSectionType.KERNEL:    
                    image_hasher.update(section_buffer)
                    bootstrap_hasher.update(section_buffer)
                elif section_type == EifSectionType.CMD_LINE:
                    image_hasher.update(section_buffer)
                    bootstrap_hasher.update(section_buffer)
                elif section_type == EifSectionType.RAM_DISK:
                    image_hasher.update(section_buffer)
                    if ram_disk_id == 0:
                        bootstrap_hasher.update(section_buffer)
                    else:
                        app_hasher.update(section_buffer)
                    ram_disk_id +=1
                elif section_type == EifSectionType.SIGNATURE:
                    # Decode signature section
                    des_sign = cbor2.loads(section_buffer)
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
                  
                    # Compte DER encoding of certificate                    
                    buffer = cert.public_bytes(encoding=serialization.Encoding.DER)
                                        
                    cert_hasher.update(buffer)

    except IOError:
        print(f'ERROR: Could not find or read the enclave image file ({eif_file_path})')
        exit(1)
    
    # Summarize expected digest values
    digests['CRC']={'expected': computed_eif_crc, 'actual': eif_crc}
    digests['PCR0']={'expected': image_hasher.finalize().hex()}
    digests['PCR1']={'expected': bootstrap_hasher.finalize().hex()}
    digests['PCR2']={'expected': app_hasher.finalize().hex()}
    digests['PCR8']={'expected': cert_hasher.finalize().hex()}
    
    if attestation_file_path:
        # Get digest values from attestation
        try:
            with open (attestation_file_path, 'rb') as attestation_file:
                attestation_doc_encoded=attestation_file.read()
        except IOError:
            print(f'ERROR: Could not find or read the attestation file ({attestation_file_path})')
            exit(1)

        attestation_doc_b64=attestation_doc_encoded.decode()
        attestation_doc=base64.urlsafe_b64decode(attestation_doc_b64)
        
        # Load COSE Sign1 object
        cose_sign_obj = cbor2.loads(attestation_doc)

        # Get the payload from the COSE object which contains public key and certificate
        # See: https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md
        attestation_doc_obj = cbor2.loads(cose_sign_obj[2])

        # Check that the attestation document contains the mandatory fields
        check_attestation_document(attestation_doc_obj, public_key = True)

        # Get signing certificate from attestation document
        cert = x509.load_der_x509_certificate(attestation_doc_obj['certificate'])
        
        # Verify signing certificate
        verify_certificate(attestation_doc_obj, cert)

        # Verify signature
        verify_signature(cose_sign_obj, cert)

        for key, pcr_val in attestation_doc_obj['pcrs'].items():
            if f'PCR{key}' in digests.keys():
                digests[f'PCR{key}']['actual'] = pcr_val.hex()

        # Compare expected (computed) values and actual values
        for key, val in digests.items():
            if val["expected"] == val["actual"]:
                print(f'{key} values match ({val["expected"]})')
            else:
                print(f'{key} values do not match ({val["expected"]}<>{val["actual"]})')
    else:
        print('Not attestation provided.')
        print('The following PCR values should match the ones obtained with the nitro-cli describe-eif command.')

        for key, val in digests.items():
            print(f'Expected {key}: {val["expected"]}')


if __name__ == '__main__':
    main()  # pylint: disable=no-value-for-parameter.
