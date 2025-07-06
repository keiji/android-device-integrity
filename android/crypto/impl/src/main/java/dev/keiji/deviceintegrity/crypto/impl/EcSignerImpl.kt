package dev.keiji.deviceintegrity.crypto.impl

import dev.keiji.deviceintegrity.crypto.contract.Signer
import java.security.PrivateKey
import java.security.Signature

class EcSignerImpl : Signer {
    companion object {
        private const val ALGORITHM_SHA256_WITH_ECDSA = "SHA256withECDSA"
    }

    override fun sign(plain: ByteArray, privateKey: PrivateKey): ByteArray {
        val signer = Signature.getInstance(ALGORITHM_SHA256_WITH_ECDSA)
        signer.initSign(privateKey)
        signer.update(plain)
        return signer.sign()
    }
}
