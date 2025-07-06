package dev.keiji.deviceintegrity.crypto.impl

import dev.keiji.deviceintegrity.crypto.contract.Signer
import java.security.PrivateKey
import java.security.Signature

class EcSignerImpl : Signer {
    override fun sign(plain: ByteArray, privateKey: PrivateKey): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey)
        signature.update(plain)
        return signature.sign()
    }
}
