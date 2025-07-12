import base64
import logging
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.backends import default_backend
from .root_certificates import ROOT_CERTIFICATES

logger = logging.getLogger(__name__)

def base64url_encode(data_bytes: bytes) -> str:
    """Encodes bytes to a Base64URL string (RFC 4648 Section 5)."""
    return base64.urlsafe_b64encode(data_bytes).decode('utf-8').rstrip('=')

def base64url_decode(base64url_string):
    """Decodes a Base64URL string to bytes."""
    padding = '=' * (4 - (len(base64url_string) % 4))
    return base64.urlsafe_b64decode(base64url_string + padding)

def decode_certificate_chain(certificate_chain_b64: list[str]) -> list[x509.Certificate]:
    """
    Decodes a list of Base64 encoded certificate strings into a list of X509Certificate objects.
    """
    decoded_certs = []
    if not certificate_chain_b64:
        raise ValueError('Input certificate chain is empty.')

    for i, cert_b64 in enumerate(certificate_chain_b64):
        if not isinstance(cert_b64, str):
            raise ValueError(f'Certificate at index {i} is not a string.')

        cert_bytes = None
        try:
            cert_bytes = base64.b64decode(cert_b64)
        except ValueError as e:
            logger.error(f'Failed to Base64 decode certificate at index {i}: {e}')
            raise ValueError(f'Invalid Base64 content for certificate at index {i}. Error: {e}')

        if cert_bytes is None:
            raise ValueError(f'Base64 decoding resulted in None for certificate at index {i}.')

        try:
            cert = x509.load_der_x509_certificate(cert_bytes)
            decoded_certs.append(cert)
        except ValueError as e:
            logger.error(f'Failed to parse DER certificate at index {i} after Base64 decoding: {e}')
            raise ValueError(f'Cannot parse certificate data at index {i} into X509 object. Error: {e}')
        except Exception as e:
            logger.error(f'Unexpected error loading certificate at index {i} into X509 object: {e}')
            raise ValueError(f'Unexpected issue with certificate data at index {i}. Error: {e}')

    if not decoded_certs:
        raise ValueError('Certificate chain is empty after attempting decoding (e.g., all inputs were invalid or chain was initially empty).')
    return decoded_certs

def validate_attestation_signature(leaf_certificate: x509.Certificate,
                                   nonce_from_store_b64url: str,
                                   nonce_b_b64url: str,
                                   signature_b64url: str) -> bool:
    """
    Validates the attestation signature.
    """
    try:
        nonce_from_store_bytes = base64url_decode(nonce_from_store_b64url)
        nonce_b_bytes = base64url_decode(nonce_b_b64url)
        signature_bytes = base64url_decode(signature_b64url)
    except Exception as e:
        logger.error(f'Failed to base64url_decode one of the signature components: {e}')
        raise ValueError(f'Invalid base64url encoding for nonce_from_store, client_nonce (nonce_b), or signature. Error: {e}')

    signed_data_bytes = nonce_from_store_bytes + nonce_b_bytes
    public_key = leaf_certificate.public_key()

    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature_bytes,
                signed_data_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            logger.info('Attestation signature validated successfully (EC).')
            return True
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature_bytes,
                signed_data_bytes,
                asym_padding.PKCS1v15(),
                hashes.SHA256()
            )
            logger.info('Attestation signature validated successfully (RSA).')
            return True
        else:
            logger.error(f'Unsupported public key type for signature verification: {type(public_key)}')
            raise ValueError('Unsupported public key type in leaf certificate for signature verification.')
    except InvalidSignature:
        logger.warning('Attestation signature verification failed: InvalidSignature.')
        raise ValueError('Attestation signature verification failed (InvalidSignature).')
    except Exception as e:
        logger.error(f'Error during attestation signature verification: {e}')
        raise ValueError(f'An unexpected error occurred during signature verification: {e}')

def derive_shared_key(
    server_private_key_pem: bytes,
    client_public_key_der: bytes,
    salt: bytes
) -> bytes:
    """
    Derives a shared AES key using ECDH and HKDF.
    """
    try:
        server_private_key = serialization.load_pem_private_key(
            server_private_key_pem,
            password=None,
            backend=default_backend()
        )
    except Exception as e:
        logger.error(f"Failed to load server private key from PEM: {e}")
        raise ValueError("Invalid server private key.") from e

    try:
        client_public_key = serialization.load_der_public_key(
            client_public_key_der,
            backend=default_backend()
        )
    except Exception as e:
        logger.error(f"Failed to load client public key from DER: {e}")
        raise ValueError("Invalid client public key.") from e

    if not isinstance(server_private_key, ec.EllipticCurvePrivateKey) or \
       not isinstance(client_public_key, ec.EllipticCurvePublicKey):
        raise ValueError("Both keys must be EC keys for ECDH.")

    try:
        shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
    except Exception as e:
        logger.error(f"ECDH key exchange failed: {e}")
        raise ValueError("Key exchange failed.") from e

    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'key-attestation-agreement',
            backend=default_backend()
        )
        aes_key = hkdf.derive(shared_secret)
        return aes_key
    except Exception as e:
        logger.error(f"HKDF key derivation failed: {e}")
        raise ValueError("Failed to derive AES key.") from e

def decrypt_data(
    aes_key: bytes,
    iv: bytes,
    encrypted_data: bytes,
    aad: bytes
) -> bytes:
    """
    Decrypts data using AES-GCM.
    """
    try:
        aesgcm = AESGCM(aes_key)
        decrypted_data = aesgcm.decrypt(iv, encrypted_data, aad)
        return decrypted_data
    except InvalidTag:
        logger.warning("AES-GCM decryption failed: Invalid authentication tag.")
        raise ValueError("Decryption failed: incorrect key or tampered data.")
    except Exception as e:
        logger.error(f"AES-GCM decryption failed with an unexpected error: {e}")
        raise ValueError(f"Decryption failed due to an unexpected error: {e}")

def _prepare_certificate_for_comparison(cert_str: str) -> str:
    """
    Prepares a PEM certificate string for comparison by normalizing it.
    - Trims leading/trailing whitespace.
    - Removes the PEM header and footer.
    - Removes all whitespace characters.
    """
    processed_str = cert_str.strip()
    if processed_str.startswith('-----BEGIN PUBLIC KEY-----'):
        processed_str = processed_str.replace('-----BEGIN PUBLIC KEY-----', '')
    if processed_str.startswith('-----BEGIN CERTIFICATE-----'):
        processed_str = processed_str.replace('-----BEGIN CERTIFICATE-----', '')
    if processed_str.endswith('-----END PUBLIC KEY-----'):
        processed_str = processed_str.replace('-----END PUBLIC KEY-----', '')
    if processed_str.endswith('-----END CERTIFICATE-----'):
        processed_str = processed_str.replace('-----END CERTIFICATE-----', '')
    return "".join(processed_str.split())

def verify_certificate_chain(certificates: list[x509.Certificate]) -> bool:
    """
    Verifies the certificate chain.
    """
    if not certificates:
        raise ValueError('Certificate chain is empty, cannot verify.')

    root_cert = certificates[-1]
    try:
        # Try to serialize as a public key first
        try:
            root_public_key = root_cert.public_key()
            root_cert_pem = root_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        except Exception:
            # If that fails, try to serialize as a full certificate
            root_cert_pem = root_cert.public_bytes(
                encoding=serialization.Encoding.PEM
            ).decode('utf-8')
    except Exception as e:
        logger.error(f"Could not serialize the root certificate to PEM: {e}")
        raise ValueError("Failed to serialize the provided root certificate for verification.")

    normalized_root_cert = _prepare_certificate_for_comparison(root_cert_pem)

    normalized_known_roots = [
        _prepare_certificate_for_comparison(cert) for cert in ROOT_CERTIFICATES
    ]

    if normalized_root_cert not in normalized_known_roots:
        # For backwards compatibility, we also check the public key of the root certificate
        try:
            root_public_key = root_cert.public_key()
            root_public_key_pem = root_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            normalized_root_public_key = _prepare_certificate_for_comparison(root_public_key_pem)
            if normalized_root_public_key not in normalized_known_roots:
                logger.warning("The root certificate of the chain is not in the list of trusted root certificates.")
                raise ValueError("Untrusted root certificate.")
        except Exception:
             raise ValueError("Untrusted root certificate.")


    logger.info("Root certificate is trusted.")

    if len(certificates) == 1:
        logger.info("Certificate chain consists of a single, trusted root certificate.")
        return True

    for i in range(len(certificates) - 1):
        subject_cert = certificates[i]
        try:
            issuer_cert = certificates[i+1]
        except IndexError:
            logger.error("Logic error in certificate chain verification loop.")
            raise ValueError("Internal error in certificate chain verification.")

        if subject_cert.issuer != issuer_cert.subject:
            logger.warning(f"Certificate chain validation failed: Issuer of cert {i} ('{subject_cert.issuer}') does not match subject of cert {i+1} ('{issuer_cert.subject}').")
            raise ValueError(f"Certificate chain validation failed: Issuer of certificate at index {i} does not match subject of certificate at index {i+1}.")

        issuer_public_key = issuer_cert.public_key()

        try:
            if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                issuer_public_key.verify(
                    subject_cert.signature,
                    subject_cert.tbs_certificate_bytes,
                    ec.ECDSA(subject_cert.signature_hash_algorithm)
                )
            elif isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    subject_cert.signature,
                    subject_cert.tbs_certificate_bytes,
                    asym_padding.PKCS1v15(),
                    subject_cert.signature_hash_algorithm
                )
            else:
                logger.error(f'Unsupported public key type in issuer certificate (index {i+1}) for chain validation: {type(issuer_public_key)}')
                raise ValueError(f'Certificate chain validation failed: Unsupported public key type in issuer certificate at index {i+1}.')

            logger.info(f'Verified certificate {i}\'s signature with certificate {i+1}\'s public key.')
        except InvalidSignature:
            logger.warning(f'Certificate chain validation failed: Cert {i} not signed by cert {i+1} (InvalidSignature).')
            raise ValueError(f'Certificate chain validation failed: Signature of certificate at index {i} is not valid by certificate at index {i+1}.')
        except Exception as e:
            logger.error(f'Error during certificate chain validation (cert {i} by cert {i+1}): {e}')
            raise ValueError(f'An unexpected error occurred during certificate chain validation: {e}')

    logger.info('Certificate chain verified successfully.')
    return True
