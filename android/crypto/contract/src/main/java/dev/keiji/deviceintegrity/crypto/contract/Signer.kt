package dev.keiji.deviceintegrity.crypto.contract

import java.security.PrivateKey
import java.security.PublicKey

interface Signer {
    fun sign(plain: ByteArray, privateKey: PrivateKey): ByteArray
}
