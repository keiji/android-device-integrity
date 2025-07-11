package com.example.crypto.impl

import com.example.crypto.contract.SharedKeyDerivator
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject

/**
 * Implements SharedKeyDerivator using HKDF (HMAC-based Key Derivation Function)
 * with standard Android APIs.
 */
class HkdfKeyDerivator @Inject constructor() : SharedKeyDerivator {

    companion object {
        private const val KEY_AGREEMENT_ALGORITHM = "ECDH"
        private const val HMAC_ALGORITHM = "HmacSHA256"
        private const val DERIVED_KEY_SIZE_BYTES = 32 // 256 bits
        private const val HASH_LENGTH_BYTES = 32 // SHA-256 output length
    }

    override fun deriveKey(publicKey: PublicKey, privateKey: PrivateKey, salt: ByteArray?): ByteArray {
        // 1. Perform Key Agreement (ECDH)
        val sharedSecret = performKeyAgreement(publicKey, privateKey)

        // 2. Perform HKDF (RFC 5869)
        return hkdf(sharedSecret, salt, null, DERIVED_KEY_SIZE_BYTES)
    }

    private fun performKeyAgreement(publicKey: PublicKey, privateKey: PrivateKey): ByteArray {
        try {
            val keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM)
            keyAgreement.init(privateKey)
            keyAgreement.doPhase(publicKey, true)
            return keyAgreement.generateSecret()
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException("ECDH algorithm not found", e)
        } catch (e: InvalidKeyException) {
            throw IllegalArgumentException("Invalid key for ECDH", e)
        }
    }

    /**
     * HKDF (HMAC-based Key Derivation Function) - RFC 5869.
     *
     * @param ikm Input Keying Material.
     * @param salt Optional salt value (a non-secret random value). If not provided, it is set to a byte array of HASH_LENGTH_BYTES zeros.
     * @param info Optional context and application specific information.
     * @param length Desired output key length in bytes. Max length is 255 * HASH_LENGTH_BYTES.
     * @return Output Keying Material (OKM) of 'length' bytes.
     */
    private fun hkdf(ikm: ByteArray, salt: ByteArray?, info: ByteArray?, length: Int): ByteArray {
        // --- HKDF-Extract ---
        val actualSalt = salt ?: ByteArray(HASH_LENGTH_BYTES) // If salt is not provided, use a string of HashLen zeros.
        val prk = hmac(actualSalt, ikm) // PseudoRandom Key

        // --- HKDF-Expand ---
        if (length < 0) throw IllegalArgumentException("Requested key length must be non-negative.")
        if (length > 255 * HASH_LENGTH_BYTES) {
            throw IllegalArgumentException("Requested key length $length is too long for $HMAC_ALGORITHM.")
        }

        val okm = ByteArray(length) // Output Keying Material
        var t = ByteArray(0)
        var n = 0 // Iteration counter

        while (t.size < length) {
            n++
            if (n > 255) { // Should be caught by the length check above, but good for safety.
                throw IllegalStateException("HKDF expansion iteration limit reached.")
            }
            val hmacInput = t + (info ?: ByteArray(0)) + byteArrayOf(n.toByte())
            t = hmac(prk, hmacInput)
            System.arraycopy(t, 0, okm, (n - 1) * HASH_LENGTH_BYTES, minOf(t.size, length - (n - 1) * HASH_LENGTH_BYTES))
        }
        return okm
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        try {
            val mac = Mac.getInstance(HMAC_ALGORITHM)
            mac.init(SecretKeySpec(key, HMAC_ALGORITHM))
            return mac.doFinal(data)
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException("$HMAC_ALGORITHM not found", e)
        } catch (e: InvalidKeyException) {
            throw IllegalArgumentException("Invalid key for HMAC", e)
        }
    }
}
