package dev.keiji.deviceintegrity.ui.util

import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

object KeyUtils {

    fun convertBytesToPublicKey(keyBytes: ByteArray, algorithm: String): PublicKey {
        val keyFactory = KeyFactory.getInstance(algorithm)
        val keySpec = X509EncodedKeySpec(keyBytes)
        return keyFactory.generatePublic(keySpec)
    }

    fun convertBytesToSecretKey(keyBytes: ByteArray, algorithm: String = "AES"): SecretKey {
        // Assuming AES for derived keys as a common default.
        // The algorithm parameter allows specifying others like "HmacSHA256" if needed.
        return SecretKeySpec(keyBytes, algorithm)
    }
}
