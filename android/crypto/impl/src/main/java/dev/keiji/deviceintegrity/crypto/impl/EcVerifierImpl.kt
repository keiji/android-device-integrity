package dev.keiji.deviceintegrity.crypto.impl

import dev.keiji.deviceintegrity.crypto.contract.Verifier
import java.security.PublicKey
import java.security.Signature

class EcVerifierImpl : Verifier {
    companion object {
        private const val ALGORITHM_SHA256_WITH_ECDSA = "SHA256withECDSA"
    }

    override fun verify(signature: ByteArray, plain: ByteArray, publicKey: PublicKey): Boolean {
        val verifier = Signature.getInstance(ALGORITHM_SHA256_WITH_ECDSA)
        verifier.initVerify(publicKey)
        verifier.update(plain)
        return verifier.verify(signature)
    }
}
