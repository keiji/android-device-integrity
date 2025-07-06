package dev.keiji.deviceintegrity.util

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.SecureRandom

class Base64UrlEncoderTest {

    @Test
    fun `encodeNoPadding produces correct Base64URL string without padding`() {
        // Test with known vectors for URL safe no padding
        // "Many hands make light work." -> TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu
        val testData1 = "Many hands make light work.".toByteArray(Charsets.UTF_8)
        val expectedEncoded1 = "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu"
        assertEquals(expectedEncoded1, Base64UrlEncoder.encodeNoPadding(testData1))

        // "abc" -> "YWJj"
        val testData2 = "abc".toByteArray(Charsets.UTF_8)
        val expectedEncoded2 = "YWJj"
        assertEquals(expectedEncoded2, Base64UrlEncoder.encodeNoPadding(testData2))

        // "ab" -> "YWI" (standard Base64: YWI=)
        val testData3 = "ab".toByteArray(Charsets.UTF_8)
        val expectedEncoded3 = "YWI"
        assertEquals(expectedEncoded3, Base64UrlEncoder.encodeNoPadding(testData3))

        // "a" -> "YQ" (standard Base64: YQ==)
        val testData4 = "a".toByteArray(Charsets.UTF_8)
        val expectedEncoded4 = "YQ"
        assertEquals(expectedEncoded4, Base64UrlEncoder.encodeNoPadding(testData4))

        // Test with empty byte array
        val testData5 = byteArrayOf()
        val expectedEncoded5 = ""
        assertEquals(expectedEncoded5, Base64UrlEncoder.encodeNoPadding(testData5))

        // Test with bytes that would normally include + or / in standard Base64
        // Java's getUrlEncoder replaces + with - and / with _
        // byte array [251, 239, 191] (0xfb, 0xef, 0xbf) -> standard is "+/+" -> URL safe is "-_-"
        val testData6 = byteArrayOf(251.toByte(), 239.toByte(), 191.toByte())
        val expectedEncoded6 = "-_-"
        assertEquals(expectedEncoded6, Base64UrlEncoder.encodeNoPadding(testData6))
    }

    @Test
    fun `decode handles Base64URL string with or without padding`() {
        // Case 1: No padding, original "YWJj" -> "abc"
        val encoded1 = "YWJj"
        val expectedDecoded1 = "abc".toByteArray(Charsets.UTF_8)
        assertArrayEquals(expectedDecoded1, Base64UrlEncoder.decode(encoded1))

        // Case 2: Input "YWI" (from "ab", standard would be YWI=)
        val encoded2 = "YWI"
        val expectedDecoded2 = "ab".toByteArray(Charsets.UTF_8)
        assertArrayEquals(expectedDecoded2, Base64UrlEncoder.decode(encoded2))

        // Case 3: Input "YQ" (from "a", standard would be YQ==)
        val encoded3 = "YQ"
        val expectedDecoded3 = "a".toByteArray(Charsets.UTF_8)
        assertArrayEquals(expectedDecoded3, Base64UrlEncoder.decode(encoded3))

        val encoded4 = "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu"
        val expectedDecoded4 = "Many hands make light work.".toByteArray(Charsets.UTF_8)
        assertArrayEquals(expectedDecoded4, Base64UrlEncoder.decode(encoded4))

        val encoded5 = ""
        val expectedDecoded5 = byteArrayOf()
        assertArrayEquals(expectedDecoded5, Base64UrlEncoder.decode(encoded5))

        // "hello" -> "aGVsbG8" (standard aGVsbG8=)
        val encoded6 = "aGVsbG8"
        val expectedDecoded6 = "hello".toByteArray(Charsets.UTF_8)
        assertArrayEquals(expectedDecoded6, Base64UrlEncoder.decode(encoded6))

        // Test with URL safe characters generated from original + /
        // byteArrayOf(251.toByte(), 239.toByte(), 191.toByte()) -> encoded to "-_-"
        val encoded7 = "-_-"
        val expectedDecoded7 = byteArrayOf(251.toByte(), 239.toByte(), 191.toByte())
        assertArrayEquals(expectedDecoded7, Base64UrlEncoder.decode(encoded7))

        // Test if standard Base64 with padding is passed to URL decoder
        // The java.util.Base64.getUrlDecoder() can decode strings with padding.
        val encoded8 = "YWI="
        assertArrayEquals(expectedDecoded2, Base64UrlEncoder.decode(encoded8)) // expected is "ab"
    }

    @Test
    fun `encode and decode are symmetric`() {
        val originalData = "This is a test string with various characters !@#\$%^&*()_+=-`~[]{};':\",./<>?".toByteArray(Charsets.UTF_8)
        val encoded = Base64UrlEncoder.encodeNoPadding(originalData)
        val decoded = Base64UrlEncoder.decode(encoded)
        assertArrayEquals(originalData, decoded)

        val secureRandom = SecureRandom()
        val originalData2 = ByteArray(128)
        secureRandom.nextBytes(originalData2)
        val encoded2 = Base64UrlEncoder.encodeNoPadding(originalData2)
        val decoded2 = Base64UrlEncoder.decode(encoded2)
        assertArrayEquals(originalData2, decoded2)

        val originalData3 = byteArrayOf()
        val encoded3 = Base64UrlEncoder.encodeNoPadding(originalData3)
        val decoded3 = Base64UrlEncoder.decode(encoded3)
        assertArrayEquals(originalData3, decoded3)
    }
}
