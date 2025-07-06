package dev.keiji.deviceintegrity.ui.main.keyattestation

import app.cash.turbine.test
import dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationRequest
import dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationResponse
import dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationVerifyApiClient
import dev.keiji.deviceintegrity.util.Base64UrlEncoder
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class KeyAttestationViewModelTest {

    private lateinit var viewModel: KeyAttestationViewModel
    private val mockApiClient: KeyAttestationVerifyApiClient = mockk()
    private val testDispatcher = StandardTestDispatcher()

    // Companion object to access ViewModel's private constants if needed, or use literals.
    // For MAX_NONCE_LENGTH_BYTES, we'll use the literal 32 as it's private.
    private val defaultNonceLengthBytes = 16

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        viewModel = KeyAttestationViewModel(mockApiClient)
        // Advance past the init block's coroutine launch for nonce generation
        testDispatcher.scheduler.advanceUntilIdle()
    }

    @Test
    fun `initial state is correct`() = runTest {
        // ViewModel is initialized in setUp, including initial nonce generation
        val state = viewModel.uiState.value

        assertEquals("Initial nonce should be of default hex length", defaultNonceLengthBytes * 2, state.nonce.length)
        assertTrue("Nonce should be valid initially", state.isNonceValid)
        assertNull("Attestation result should be null initially", state.attestationResult)
        assertFalse("Should not be loading initially", state.isLoading)
    }

    @Test
    fun `updateNonce with valid hex updates state correctly`() = runTest {
        viewModel.updateNonce("1234ABCD")
        val state = viewModel.uiState.value
        assertEquals("1234ABCD", state.nonce)
        assertTrue(state.isNonceValid)
    }

    @Test
    fun `updateNonce with odd length hex updates state and marks invalid`() = runTest {
        viewModel.updateNonce("123")
        val state = viewModel.uiState.value
        assertEquals("123", state.nonce)
        assertFalse(state.isNonceValid)
    }

    @Test
    fun `updateNonce with invalid hex characters updates state, marks invalid and sends event`() = runTest {
        viewModel.eventFlow.test {
            viewModel.updateNonce("XYZ123") // Contains invalid 'X', 'Y', 'Z'
            val state = viewModel.uiState.value
            assertEquals("XYZ123", state.nonce) // The VM keeps the invalid input in the state for the user to see
            assertFalse(state.isNonceValid)
            assertEquals("Nonce contains invalid characters.", (awaitItem() as KeyAttestationUiEvent.ShowToast).message)
        }
    }

    @Test
    fun `updateNonce with too long hex updates state, marks invalid and sends event`() = runTest {
        val initialNonce = viewModel.uiState.value.nonce
        val longNonce = "A".repeat(32 * 2 + 2) // MAX_NONCE_LENGTH_BYTES (32) * 2 + 2 = 66

        viewModel.eventFlow.test {
            viewModel.updateNonce(longNonce)
            // Note: The current ViewModel's updateNonce for "too long" does:
            // 1. Updates _uiState with isNonceValid = false
            // 2. Sends toast
            // 3. Returns WITHOUT updating the actual nonce field in the state.
            // So the nonce field should remain the initialNonce.
            // And isNonceValid should be false.

            val state = viewModel.uiState.value
            assertEquals("Nonce in state should remain the initial valid one", initialNonce, state.nonce)
            assertFalse("isNonceValid should be false due to excessive length", state.isNonceValid)
            assertEquals("Nonce is too long.", (awaitItem() as KeyAttestationUiEvent.ShowToast).message)
        }
    }

    @Test
    fun `submit success - nonce encoded correctly, UI state updated`() = runTest {
        val testNonceHex = "0102030405"
        viewModel.updateNonce(testNonceHex)
        testDispatcher.scheduler.advanceUntilIdle()

        val nonceBytes = byteArrayOf(1, 2, 3, 4, 5)
        val expectedChallenge = Base64UrlEncoder.encodeNoPadding(nonceBytes)
        val dummyAttestationStatement = "DUMMY_ATTESTATION_STATEMENT"
        val expectedRequest = KeyAttestationRequest(
            attestationStatement = dummyAttestationStatement,
            challenge = expectedChallenge
        )
        val mockResponse = KeyAttestationResponse(isValid = true, errorMessages = null)

        coEvery { mockApiClient.verifyAttestation(expectedRequest) } returns mockResponse

        viewModel.eventFlow.test {
            viewModel.submit()
            testDispatcher.scheduler.advanceUntilIdle()

            val state = viewModel.uiState.value
            assertFalse(state.isLoading)
            assertEquals("Valid: true, Errors: None", state.attestationResult)
            assertEquals("Attestation check completed.", (awaitItem() as KeyAttestationUiEvent.ShowToast).message)
        }
        coVerify { mockApiClient.verifyAttestation(expectedRequest) }
    }

    @Test
    fun `submit failure - API error, UI state updated`() = runTest {
        val testNonceHex = "AABBCC"
        viewModel.updateNonce(testNonceHex)
        testDispatcher.scheduler.advanceUntilIdle()

        val nonceBytes = byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte())
        val expectedChallenge = Base64UrlEncoder.encodeNoPadding(nonceBytes)
        val dummyAttestationStatement = "DUMMY_ATTESTATION_STATEMENT"
        val expectedRequest = KeyAttestationRequest(attestationStatement = dummyAttestationStatement, challenge = expectedChallenge)

        val exceptionMessage = "Network error"
        coEvery { mockApiClient.verifyAttestation(expectedRequest) } throws RuntimeException(exceptionMessage)

        viewModel.eventFlow.test {
            viewModel.submit()
            testDispatcher.scheduler.advanceUntilIdle()

            val state = viewModel.uiState.value
            assertFalse(state.isLoading)
            assertEquals("Error: $exceptionMessage", state.attestationResult)
            assertEquals("Attestation failed: $exceptionMessage", (awaitItem() as KeyAttestationUiEvent.ShowToast).message)
        }
        coVerify { mockApiClient.verifyAttestation(expectedRequest) }
    }

    @Test
    fun `submit with empty or invalid nonce - shows toast, no API call`() = runTest {
        // Force an invalid nonce state (e.g. odd length) which also makes nonceByteArray empty
        viewModel.updateNonce("123")
        testDispatcher.scheduler.advanceUntilIdle()

        viewModel.eventFlow.test {
            viewModel.submit()
            testDispatcher.scheduler.advanceUntilIdle()
            assertEquals("Nonce is empty or invalid.", (awaitItem() as KeyAttestationUiEvent.ShowToast).message)
        }
        coVerify(exactly = 0) { mockApiClient.verifyAttestation(any()) }
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }
}
