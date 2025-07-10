package dev.keiji.deviceintegrity.crypto.impl

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class CryptoImplTest {

    private val encrypter = EncryptImpl()
    private val decrypter = DecryptImpl()

    private fun generateAesKey(): SecretKey {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256) // AES-256
        return keyGen.generateKey()
    }

    @Test
    fun `encrypt and decrypt successfully with no AAD`() {
        val secretKey = generateAesKey()
        val plainText = "This is a secret message.".toByteArray()

        val encrypted = encrypter.encrypt(plainText, secretKey)
        val decrypted = decrypter.decrypt(encrypted, secretKey)

        assertArrayEquals(plainText, decrypted)
    }

    @Test
    fun `encrypt and decrypt successfully with AAD`() {
        val secretKey = generateAesKey()
        val plainText = "This is another secret message.".toByteArray()
        val aad = "Additional Authentication Data".toByteArray()

        val encrypted = encrypter.encrypt(plainText, secretKey, aad)
        val decrypted = decrypter.decrypt(encrypted, secretKey, aad)

        assertArrayEquals(plainText, decrypted)
    }

    @Test
    fun `decrypt fails with incorrect key`() {
        val key1 = generateAesKey()
        val key2 = generateAesKey()
        val plainText = "Sensitive information.".toByteArray()

        val encrypted = encrypter.encrypt(plainText, key1)

        assertThrows(AEADBadTagException::class.java) {
            decrypter.decrypt(encrypted, key2)
        }
    }

    @Test
    fun `decrypt fails with tampered ciphertext`() {
        val secretKey = generateAesKey()
        val plainText = "Don't tamper with this!".toByteArray()

        val encrypted = encrypter.encrypt(plainText, secretKey)
        encrypted[encrypted.size - 1] = encrypted[encrypted.size - 1].inc() // Tamper last byte

        assertThrows(AEADBadTagException::class.java) {
            decrypter.decrypt(encrypted, secretKey)
        }
    }

    @Test
    fun `decrypt fails with tampered IV`() {
        val secretKey = generateAesKey()
        val plainText = "IV tampering test".toByteArray()

        val encrypted = encrypter.encrypt(plainText, secretKey)
        encrypted[0] = encrypted[0].inc() // Tamper first byte of IV

        assertThrows(AEADBadTagException::class.java) {
            decrypter.decrypt(encrypted, secretKey)
        }
    }


    @Test
    fun `decrypt fails with incorrect AAD`() {
        val secretKey = generateAesKey()
        val plainText = "AAD mismatch test".toByteArray()
        val aad1 = "Correct AAD".toByteArray()
        val aad2 = "Incorrect AAD".toByteArray()

        val encrypted = encrypter.encrypt(plainText, secretKey, aad1)

        assertThrows(AEADBadTagException::class.java) {
            decrypter.decrypt(encrypted, secretKey, aad2)
        }
    }

    @Test
    fun `decrypt fails if AAD was used in encryption but not in decryption`() {
        val secretKey = generateAesKey()
        val plainText = "AAD missing in decryption".toByteArray()
        val aad = "AAD Present".toByteArray()

        val encrypted = encrypter.encrypt(plainText, secretKey, aad)

        assertThrows(AEADBadTagException::class.java) {
            decrypter.decrypt(encrypted, secretKey, null)
        }
    }

    @Test
    fun `decrypt fails if AAD was not used in encryption but provided in decryption`() {
        val secretKey = generateAesKey()
        val plainText = "AAD provided unexpectedly".toByteArray()
        val aad = "Unexpected AAD".toByteArray()

        val encrypted = encrypter.encrypt(plainText, secretKey, null)

        assertThrows(AEADBadTagException::class.java) {
            decrypter.decrypt(encrypted, secretKey, aad)
        }
    }

    @Test
    fun `encrypted output contains IV and ciphertext`() {
        val secretKey = generateAesKey()
        val plainText = "Test IV concatenation".toByteArray()
        val ivSize = 12 // As defined in EncryptImpl

        val encrypted = encrypter.encrypt(plainText, secretKey)

        assertTrue("Encrypted data should be larger than plaintext + IV size", encrypted.size > plainText.size + ivSize)
        assertEquals("Encrypted data size should be IV size + ciphertext size + auth tag size (16 bytes for 128-bit tag)",
            ivSize + plainText.size + 16, encrypted.size)

    }
}
