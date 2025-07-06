package dev.keiji.deviceintegrity.crypto.impl

import dev.keiji.deviceintegrity.crypto.contract.Verifier
import java.security.PublicKey
import java.security.Signature

class EcVerifierImpl : Verifier {
    override fun verify(signature: ByteArray, plain: ByteArray, publicKey: PublicKey): Boolean {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initVerify(publicKey)
        sig.update(plain)
        return sig.verify(signature)
    }
}
