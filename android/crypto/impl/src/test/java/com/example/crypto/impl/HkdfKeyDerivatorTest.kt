package com.example.crypto.impl

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec

class HkdfKeyDerivatorTest {

    private lateinit var derivator: HkdfKeyDerivator

    // Using NIST P-256 curve for ECDH
    private val ecSpec = ECGenParameterSpec("secp256r1")

    @Before
    fun setUp() {
        // Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider()) // Not needed
        derivator = HkdfKeyDerivator()
    }

    private fun generateEcKeyPair(): KeyPair {
        val g = KeyPairGenerator.getInstance("EC") // Use default provider
        g.initialize(ecSpec, SecureRandom())
        return g.generateKeyPair()
    }

    @Test
    fun `deriveKey returns a key of correct length`() {
        val keyPair1 = generateEcKeyPair()
        val keyPair2 = generateEcKeyPair()

        val derivedKey = derivator.deriveKey(keyPair2.public, keyPair1.private)
        assertNotNull(derivedKey)
        assertEquals(32, derivedKey.size) // Expecting 256-bit key
    }

    @Test
    fun `deriveKey is consistent for same inputs`() {
        val keyPair1 = generateEcKeyPair()
        val keyPair2 = generateEcKeyPair()

        val derivedKey1 = derivator.deriveKey(keyPair2.public, keyPair1.private)
        val derivedKey2 = derivator.deriveKey(keyPair2.public, keyPair1.private)

        assertArrayEquals(derivedKey1, derivedKey2)
    }

    @Test
    fun `deriveKey produces different keys for different key pairs`() {
        val keyPair1 = generateEcKeyPair()
        val keyPair2 = generateEcKeyPair()
        val keyPair3 = generateEcKeyPair() // A different party

        // Key derived between party 1 and party 2
        val derivedKey12 = derivator.deriveKey(keyPair2.public, keyPair1.private)

        // Key derived between party 1 and party 3
        val derivedKey13 = derivator.deriveKey(keyPair3.public, keyPair1.private)

        assertNotEquals(derivedKey12.contentToString(), derivedKey13.contentToString())
    }

    @Test
    fun `deriveKey with same salt produces same key`() {
        val keyPair1 = generateEcKeyPair()
        val keyPair2 = generateEcKeyPair()
        val salt = "test_salt".toByteArray()

        val derivedKey1 = derivator.deriveKey(keyPair2.public, keyPair1.private, salt)
        val derivedKey2 = derivator.deriveKey(keyPair2.public, keyPair1.private, salt)

        assertArrayEquals(derivedKey1, derivedKey2)
    }

    @Test
    fun `deriveKey with different salts produces different keys`() {
        val keyPair1 = generateEcKeyPair()
        val keyPair2 = generateEcKeyPair()
        val salt1 = "salt1".toByteArray()
        val salt2 = "salt2".toByteArray()

        val derivedKey1 = derivator.deriveKey(keyPair2.public, keyPair1.private, salt1)
        val derivedKey2 = derivator.deriveKey(keyPair2.public, keyPair1.private, salt2)

        assertNotEquals(derivedKey1.contentToString(), derivedKey2.contentToString())
    }

    @Test
    fun `deriveKey with and without salt produces different keys`() {
        val keyPair1 = generateEcKeyPair()
        val keyPair2 = generateEcKeyPair()
        val salt = "test_salt".toByteArray()

        val derivedKeyWithSalt = derivator.deriveKey(keyPair2.public, keyPair1.private, salt)
        val derivedKeyWithoutSalt = derivator.deriveKey(keyPair2.public, keyPair1.private, null)

        assertNotEquals(derivedKeyWithSalt.contentToString(), derivedKeyWithoutSalt.contentToString())
    }

    @Test
    fun `deriveKey works for both sides of key exchange (ECDH property)`() {
        val keyPairA = generateEcKeyPair() // Alice's key pair
        val keyPairB = generateEcKeyPair() // Bob's key pair

        // Alice computes shared key using Bob's public key and her private key
        val derivedKeyAlice = derivator.deriveKey(keyPairB.public, keyPairA.private)

        // Bob computes shared key using Alice's public key and his private key
        val derivedKeyBob = derivator.deriveKey(keyPairA.public, keyPairB.private)

        assertArrayEquals(derivedKeyAlice, derivedKeyBob)
    }

    @Test
    fun `deriveKey with salt works for both sides of key exchange`() {
        val keyPairA = generateEcKeyPair()
        val keyPairB = generateEcKeyPair()
        val salt = "common_salt".toByteArray()

        val derivedKeyAlice = derivator.deriveKey(keyPairB.public, keyPairA.private, salt)
        val derivedKeyBob = derivator.deriveKey(keyPairA.public, keyPairB.private, salt)

        assertArrayEquals(derivedKeyAlice, derivedKeyBob)
    }
}
