package dev.keiji.deviceintegrity.crypto.impl.signer

import dev.keiji.deviceintegrity.crypto.contract.Signer
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.RSAKey

class RsaSignerImpl : Signer {
    override fun sign(plain: ByteArray, privateKey: PrivateKey): ByteArray {
        if (privateKey !is RSAKey) {
            throw IllegalArgumentException("PrivateKey must be an instance of RSAKey.")
        }

        val signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(privateKey)
        signature.update(plain)
        return signature.sign()
    }
}
