package dev.keiji.deviceintegrity.repository.contract

import java.security.KeyPair

interface RsaKeyPairRepository {
    suspend fun getKeyPair(alias: String): KeyPair?
    suspend fun removeKeyPair(alias: String)
    suspend fun generateKeyPair(challenge: ByteArray): KeyPairData
}
