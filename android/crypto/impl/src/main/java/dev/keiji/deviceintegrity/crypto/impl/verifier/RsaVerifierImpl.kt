package dev.keiji.deviceintegrity.crypto.impl.verifier

import dev.keiji.deviceintegrity.crypto.contract.Verifier
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.RSAKey

class RsaVerifierImpl : Verifier {
    override fun verify(signature: ByteArray, plain: ByteArray, publicKey: PublicKey): Boolean {
        if (publicKey !is RSAKey) {
            throw IllegalArgumentException("PublicKey must be an instance of RSAKey.")
        }

        val signatureInstance = Signature.getInstance("SHA256withRSA")
        signatureInstance.initVerify(publicKey)
        signatureInstance.update(plain)
        return signatureInstance.verify(signature)
    }
}
