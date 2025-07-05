package dev.keiji.deviceintegrity.repository.contract

import java.security.KeyStore
import java.security.cert.X509Certificate

interface KeyPairRepository {
    suspend fun generateKeyPair(nonce: ByteArray): KeyPairData
    fun getKeyPair(keyAlias: String): KeyStore.Entry?
    fun removeKeyPair(keyAlias: String)
}
