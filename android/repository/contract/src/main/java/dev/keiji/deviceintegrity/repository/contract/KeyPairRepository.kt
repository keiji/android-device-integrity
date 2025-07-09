package dev.keiji.deviceintegrity.repository.contract

import java.security.KeyPair

interface KeyPairRepository {
    suspend fun getKeyPair(alias: String): KeyPair?
    suspend fun removeKeyPair(alias: String)
    suspend fun generateEcKeyPair(challenge: ByteArray): KeyPairData
    suspend fun generateRsaKeyPair(challenge: ByteArray): KeyPairData
}
