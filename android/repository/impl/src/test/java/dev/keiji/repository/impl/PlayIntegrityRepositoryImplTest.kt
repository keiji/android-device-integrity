package dev.keiji.repository.impl

import dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationRequest
import dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationResponse
import dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationVerifyApiClient
import dev.keiji.deviceintegrity.api.playintegrity.CreateNonceRequest
import dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo
import dev.keiji.deviceintegrity.api.playintegrity.NonceResponse
import dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityResponseWrapper
import dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityTokenVerifyApiClient
import dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo
import dev.keiji.deviceintegrity.api.playintegrity.ServerVerificationPayload
import dev.keiji.deviceintegrity.api.playintegrity.StandardVerifyRequest
import dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal
import dev.keiji.deviceintegrity.api.playintegrity.VerifyTokenRequest
import dev.keiji.repository.contract.exception.ServerException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException

@ExperimentalCoroutinesApi
class PlayIntegrityRepositoryImplTest {

    private lateinit var mockKeyAttestationApiClient: KeyAttestationVerifyApiClient
    private lateinit var mockPlayIntegrityTokenVerifyApiClient: PlayIntegrityTokenVerifyApiClient
    private lateinit var repository: PlayIntegrityRepositoryImpl

    // Dummy data for tests
    private val dummyDeviceInfo = DeviceInfo("brand", "model", "device", "product", "manufacturer", "hardware", "board", "bootloader", "release", 30, "fingerprint", "patch")
    private val dummySecurityInfo = SecurityInfo(true, true, true, true)
    private val dummyTokenPayloadExternal = TokenPayloadExternal(null, null, null, null, null)
    private val dummyPlayIntegrityResponseWrapper = PlayIntegrityResponseWrapper(dummyTokenPayloadExternal)


    @Before
    fun setUp() {
        mockKeyAttestationApiClient = mock()
        mockPlayIntegrityTokenVerifyApiClient = mock()
        repository = PlayIntegrityRepositoryImpl(mockKeyAttestationApiClient, mockPlayIntegrityTokenVerifyApiClient)
    }

    // --- getIntegrityVerdictStandard Tests ---

    @Test
    fun `getIntegrityVerdictStandard success should return ServerVerificationPayload`() = runTest {
        val expectedResponse = ServerVerificationPayload(dummyDeviceInfo, dummyPlayIntegrityResponseWrapper, dummySecurityInfo)
        whenever(mockPlayIntegrityTokenVerifyApiClient.verifyTokenStandard(any())).thenReturn(expectedResponse)

        val result = repository.getIntegrityVerdictStandard("token", "sid", "binding", dummyDeviceInfo, dummySecurityInfo)
        assertEquals(expectedResponse, result)
    }

    @Test
    fun `getIntegrityVerdictStandard httpException should throw ServerException`() = runTest {
        val httpException = HttpException(Response.error<ServerVerificationPayload>(400, "Error".toResponseBody("text/plain".toMediaTypeOrNull())))
        whenever(mockPlayIntegrityTokenVerifyApiClient.verifyTokenStandard(any())).thenThrow(httpException)

        val exception = assertThrows(ServerException::class.java) {
            runTest {  repository.getIntegrityVerdictStandard("token", "sid", "binding", dummyDeviceInfo, dummySecurityInfo) }
        }
        assertEquals(400, exception.errorCode)
        assertEquals("Error", exception.errorMessage)
    }

    @Test
    fun `getIntegrityVerdictStandard ioException should throw IOException`() = runTest {
        val ioException = IOException("Network error")
        whenever(mockPlayIntegrityTokenVerifyApiClient.verifyTokenStandard(any())).thenThrow(ioException)

        assertThrows(IOException::class.java) {
            runTest { repository.getIntegrityVerdictStandard("token", "sid", "binding", dummyDeviceInfo, dummySecurityInfo) }
        }
    }

    // --- getIntegrityVerdictClassic Tests ---
    @Test
    fun `getIntegrityVerdictClassic success should return ServerVerificationPayload`() = runTest {
        val expectedResponse = ServerVerificationPayload(dummyDeviceInfo, dummyPlayIntegrityResponseWrapper, dummySecurityInfo)
        whenever(mockPlayIntegrityTokenVerifyApiClient.verifyTokenClassic(any())).thenReturn(expectedResponse)

        val result = repository.getIntegrityVerdictClassic("token", "sid", dummyDeviceInfo, dummySecurityInfo)
        assertEquals(expectedResponse, result)
    }

    @Test
    fun `getIntegrityVerdictClassic httpException should throw ServerException`() = runTest {
        val httpException = HttpException(Response.error<ServerVerificationPayload>(403, "Forbidden".toResponseBody("text/plain".toMediaTypeOrNull())))
        whenever(mockPlayIntegrityTokenVerifyApiClient.verifyTokenClassic(any())).thenThrow(httpException)

        val exception = assertThrows(ServerException::class.java) {
            runTest { repository.getIntegrityVerdictClassic("token", "sid", dummyDeviceInfo, dummySecurityInfo) }
        }
        assertEquals(403, exception.errorCode)
        assertEquals("Forbidden", exception.errorMessage)
    }

    // --- prepareChallenge Tests ---
    @Test
    fun `prepareChallenge success should return NonceResponse`() = runTest {
        val expectedResponse = NonceResponse("nonce_value", 12345L)
        whenever(mockPlayIntegrityTokenVerifyApiClient.getNonce(any())).thenReturn(expectedResponse)

        val result = repository.prepareChallenge("sid")
        assertEquals(expectedResponse, result)
    }

    @Test
    fun `prepareChallenge httpException should throw ServerException`() = runTest {
        val httpException = HttpException(Response.error<NonceResponse>(500, "Server Down".toResponseBody("text/plain".toMediaTypeOrNull())))
        whenever(mockPlayIntegrityTokenVerifyApiClient.getNonce(any())).thenThrow(httpException)

        val exception = assertThrows(ServerException::class.java) {
            runTest { repository.prepareChallenge("sid") }
        }
        assertEquals(500, exception.errorCode)
        assertEquals("Server Down", exception.errorMessage)
    }

    // --- verifyClassicDeviceAttestation Tests ---
    @Test
    fun `verifyClassicDeviceAttestation success should return KeyAttestationResponse`() = runTest {
        val expectedResponse = KeyAttestationResponse(isValid = true)
        whenever(mockKeyAttestationApiClient.verifyAttestation(any())).thenReturn(expectedResponse)

        val result = repository.verifyClassicDeviceAttestation("challenge", "attestation")
        assertEquals(expectedResponse, result)
    }

    @Test
    fun `verifyClassicDeviceAttestation httpException should throw ServerException`() = runTest {
        val httpException = HttpException(Response.error<KeyAttestationResponse>(401, "Unauthorized".toResponseBody("text/plain".toMediaTypeOrNull())))
        whenever(mockKeyAttestationApiClient.verifyAttestation(any())).thenThrow(httpException)

        val exception = assertThrows(ServerException::class.java) {
            runTest { repository.verifyClassicDeviceAttestation("challenge", "attestation") }
        }
        assertEquals(401, exception.errorCode)
        assertEquals("Unauthorized", exception.errorMessage)
    }
}
