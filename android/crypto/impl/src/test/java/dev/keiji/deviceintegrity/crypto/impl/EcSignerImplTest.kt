package dev.keiji.deviceintegrity.crypto.impl

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature

class EcSignerImplTest {

    @Test
    fun sign() {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(256)
        val keyPair = keyPairGenerator.generateKeyPair()

        val plainText = "test data".toByteArray()

        val signer = EcSignerImpl()
        val signature = signer.sign(plainText, keyPair.private)

        assertNotNull(signature)

        // Verify signature to ensure it's valid
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initVerify(keyPair.public)
        sig.update(plainText)
        assertTrue(sig.verify(signature))
    }
}
