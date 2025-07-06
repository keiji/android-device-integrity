package dev.keiji.deviceintegrity.crypto.impl

import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature

class EcVerifierImplTest {

    @Test
    fun verify() {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(256)
        val keyPair = keyPairGenerator.generateKeyPair()

        val plainText = "test data".toByteArray()

        // Generate signature
        val sigGen = Signature.getInstance("SHA256withECDSA")
        sigGen.initSign(keyPair.private)
        sigGen.update(plainText)
        val signatureBytes = sigGen.sign()

        val verifier = EcVerifierImpl()
        val isValid = verifier.verify(signatureBytes, plainText, keyPair.public)

        assertTrue(isValid)
    }
}
