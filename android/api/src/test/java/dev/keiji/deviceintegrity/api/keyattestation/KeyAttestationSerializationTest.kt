package dev.keiji.deviceintegrity.api.keyattestation

import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Test

class KeyAttestationSerializationTest {

    private val gson = Gson()

    @Test
    fun testKeyAttestationRequestSerialization() {
        val request = KeyAttestationRequest(
            attestationStatement = "sampleAttestationStatement",
            challenge = "sampleChallenge"
        )
        val json = gson.toJson(request)
        assertEquals(
            "{\"attestation_statement\":\"sampleAttestationStatement\",\"challenge\":\"sampleChallenge\"}",
            json
        )
    }

    @Test
    fun testKeyAttestationResponseSerialization() {
        val response = KeyAttestationResponse(
            isValid = true,
            errorMessages = listOf("error1", "error2")
        )
        val json = gson.toJson(response)
        assertEquals(
            "{\"is_valid\":true,\"error_messages\":[\"error1\",\"error2\"]}",
            json
        )
    }

    @Test
    fun testKeyAttestationResponseDeserialization() {
        val json = "{\"is_valid\":false,\"error_messages\":[\"err3\"]}"
        val response = gson.fromJson(json, KeyAttestationResponse::class.java)
        assertEquals(false, response.isValid)
        assertEquals(listOf("err3"), response.errorMessages)
    }

    @Test
    fun testKeyAttestationResponseDeserialization_nullErrorMessages() {
        val json = "{\"is_valid\":true}"
        val response = gson.fromJson(json, KeyAttestationResponse::class.java)
        assertEquals(true, response.isValid)
        assertEquals(null, response.errorMessages)
    }
}
