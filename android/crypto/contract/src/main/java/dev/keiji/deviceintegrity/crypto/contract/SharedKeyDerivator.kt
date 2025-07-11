package dev.keiji.deviceintegrity.crypto.contract

import java.security.PrivateKey
import java.security.PublicKey

/**
 * Interface for deriving a shared key from a key pair.
 */
interface SharedKeyDerivator {
    /**
     * Derives a shared key using the provided public key, private key, and optional salt.
     *
     * @param publicKey The public key.
     * @param privateKey The private key.
     * @param salt An optional salt for the key derivation.
     * @return The derived shared key as a ByteArray.
     */
    fun deriveKey(publicKey: PublicKey, privateKey: PrivateKey, salt: ByteArray? = null): ByteArray
}
