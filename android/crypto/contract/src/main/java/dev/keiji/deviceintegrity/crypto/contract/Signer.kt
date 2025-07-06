package dev.keiji.deviceintegrity.crypto.contract

import java.security.PrivateKey

interface Signer {
    fun sign(plain: ByteArray, privateKey: PrivateKey): ByteArray
}
