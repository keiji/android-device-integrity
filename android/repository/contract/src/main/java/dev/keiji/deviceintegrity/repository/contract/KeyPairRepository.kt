package dev.keiji.deviceintegrity.repository.contract

import java.security.KeyPair
// KeyPairData is now in the same package (dev.keiji.deviceintegrity.repository.contract)
// so an explicit import like dev.keiji.deviceintegrity.repository.contract.KeyPairData is not strictly needed.

interface KeyPairRepository {
    suspend fun getKeyPair(alias: String): KeyPair?
    suspend fun removeKeyPair(alias: String)
    suspend fun generateKeyPair(challenge: ByteArray): KeyPairData
}
