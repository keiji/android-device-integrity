package dev.keiji.deviceintegrity.repository.contract

import java.security.KeyPair

interface KeyPairRepository {
    suspend fun getKeyPair(alias: String): KeyPair?
    suspend fun removeKeyPair(alias: String)
    suspend fun generateEcKeyPair(challenge: ByteArray, preferStrongBox: Boolean): KeyPairData
    suspend fun generateRsaKeyPair(challenge: ByteArray, preferStrongBox: Boolean): KeyPairData
    suspend fun generateEcdhKeyPair(challenge: ByteArray, preferStrongBox: Boolean): KeyPairData
}
