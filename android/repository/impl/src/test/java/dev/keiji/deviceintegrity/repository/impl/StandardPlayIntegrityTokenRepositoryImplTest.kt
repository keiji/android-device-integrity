package dev.keiji.deviceintegrity.repository.impl

import com.google.android.gms.tasks.Tasks
import com.google.android.play.core.integrity.StandardIntegrityManager
import dev.keiji.deviceintegrity.provider.contract.StandardIntegrityTokenProviderProvider
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.Mockito.mock
import org.mockito.Mockito.times
import org.mockito.Mockito.verify
import org.mockito.kotlin.any
import org.mockito.kotlin.whenever
import org.robolectric.RobolectricTestRunner

@ExperimentalCoroutinesApi
@RunWith(RobolectricTestRunner::class)
class StandardPlayIntegrityTokenRepositoryImplTest {

    private lateinit var mockProviderProvider: StandardIntegrityTokenProviderProvider
    private lateinit var mockTokenProvider: StandardIntegrityManager.StandardIntegrityTokenProvider
    private lateinit var mockTokenResponse: StandardIntegrityManager.StandardIntegrityToken

    private lateinit var repository: StandardPlayIntegrityTokenRepositoryImpl

    @Before
    fun setUp() {
        mockProviderProvider = mock(StandardIntegrityTokenProviderProvider::class.java)
        mockTokenProvider = mock(StandardIntegrityManager.StandardIntegrityTokenProvider::class.java)
        mockTokenResponse = mock(StandardIntegrityManager.StandardIntegrityToken::class.java)

        repository = StandardPlayIntegrityTokenRepositoryImpl(mockProviderProvider)
    }

    @Test
    fun `getToken_whenRequestFails_shouldInvalidateAndRetry`() = runTest {
        // Arrange
        val requestHash = "requestHash"
        val expectedToken = "valid_token"

        // Mock get()
        whenever(mockProviderProvider.get()).thenReturn(mockTokenProvider)

        // Mock request() failures and success
        // First call throws Exception (wrapped in Task)
        val exceptionTask = Tasks.forException<StandardIntegrityManager.StandardIntegrityToken>(RuntimeException("Expired"))
        val successTask = Tasks.forResult(mockTokenResponse)

        // We need to return different tasks on consecutive calls
        whenever(mockTokenProvider.request(any()))
            .thenReturn(exceptionTask)
            .thenReturn(successTask)

        whenever(mockTokenResponse.token()).thenReturn(expectedToken)

        // Act
        val result = repository.getToken(requestHash)

        // Assert
        assertEquals(expectedToken, result)

        // Verify invalidate was called.
        verify(mockProviderProvider).invalidate()

        // Verify get() was called twice (initial + retry)
        verify(mockProviderProvider, times(2)).get()

        // Verify request() was called twice
        verify(mockTokenProvider, times(2)).request(any())
    }
}
