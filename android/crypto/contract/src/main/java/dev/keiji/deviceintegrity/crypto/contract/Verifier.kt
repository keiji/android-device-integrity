package dev.keiji.deviceintegrity.crypto.contract

import java.security.PublicKey

interface Verifier {
    fun verify(signature: ByteArray, plain: ByteArray, publicKey: PublicKey): Boolean
}
