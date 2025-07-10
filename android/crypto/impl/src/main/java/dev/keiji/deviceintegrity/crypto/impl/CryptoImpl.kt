package dev.keiji.deviceintegrity.crypto.impl

import dev.keiji.deviceintegrity.crypto.contract.Decrypt
import dev.keiji.deviceintegrity.crypto.contract.Encrypt
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class EncryptImpl : Encrypt {
    override fun encrypt(plain: ByteArray, secretKey: SecretKey, aad: ByteArray?): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // Generate a random IV (Initialization Vector)
        val iv = ByteArray(12) // GCM recommended IV size is 12 bytes
        SecureRandom().nextBytes(iv)
        val gcmParameterSpec = GCMParameterSpec(128, iv) // 128 bit auth tag length
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec)
        aad?.let { cipher.updateAAD(it) }
        val cipherText = cipher.doFinal(plain)
        // Prepend IV to the ciphertext for use in decryption
        return iv + cipherText
    }
}

class DecryptImpl : Decrypt {
    override fun decrypt(encrypted: ByteArray, secretKey: SecretKey, aad: ByteArray?): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // Extract IV from the beginning of the encrypted data
        val iv = encrypted.copyOfRange(0, 12)
        val cipherText = encrypted.copyOfRange(12, encrypted.size)
        val gcmParameterSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec)
        aad?.let { cipher.updateAAD(it) }
        return cipher.doFinal(cipherText)
    }
}
