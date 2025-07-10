package dev.keiji.deviceintegrity.crypto.contract

import javax.crypto.SecretKey

interface Encrypt {
    fun encrypt(plain: ByteArray, secretKey: SecretKey, aad: ByteArray? = null): ByteArray
}

interface Decrypt {
    fun decrypt(encrypted: ByteArray, secretKey: SecretKey, aad: ByteArray? = null): ByteArray
}
