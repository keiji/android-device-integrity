package dev.keiji.deviceintegrity.repository

import java.security.KeyPair

interface KeyPairRepository {
    suspend fun getKeyPair(alias: String): KeyPair?
    suspend fun removeKeyPair(alias: String)
    suspend fun generateKeyPair(challenge: ByteArray): KeyPairData
}
