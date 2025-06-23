package dev.keiji.deviceintegrity.api_endpoint_settings

import dev.keiji.deviceintegrity.repository.contract.PreferencesRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

@ExperimentalCoroutinesApi
class ApiEndpointSettingsViewModelTest {

    private val testDispatcher = StandardTestDispatcher()

    private lateinit var viewModel: ApiEndpointSettingsViewModel
    private lateinit var mockPreferencesRepository: PreferencesRepository

    private val apiEndpointUrlFlow = MutableStateFlow<String?>(null)

    @Before
    fun setup() {
        Dispatchers.setMain(testDispatcher)
        mockPreferencesRepository = mock()
        whenever(mockPreferencesRepository.apiEndpointUrl).thenReturn(apiEndpointUrlFlow)

        viewModel = ApiEndpointSettingsViewModel(mockPreferencesRepository)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `apiEndpointUrl reflects repository state`() = runTest {
        val testUrl = "https://example.com"
        apiEndpointUrlFlow.value = testUrl
        assertEquals(testUrl, viewModel.apiEndpointUrl.first())

        apiEndpointUrlFlow.value = null
        assertEquals(null, viewModel.apiEndpointUrl.first())
    }

    @Test
    fun `saveApiEndpointUrl calls repository to save URL`() = runTest {
        val testUrl = "https.newurl.com"
        viewModel.saveApiEndpointUrl(testUrl)
        testDispatcher.scheduler.advanceUntilIdle() // Ensure coroutine launched by saveApiEndpointUrl completes
        verify(mockPreferencesRepository).saveApiEndpointUrl(testUrl)
    }

    @Test
    fun `initial apiEndpointUrl is null or the value from repository`() = runTest {
        // Case 1: Repository initially has null
        apiEndpointUrlFlow.value = null
        val newViewModelNull = ApiEndpointSettingsViewModel(mockPreferencesRepository)
        assertEquals(null, newViewModelNull.apiEndpointUrl.value) // Using .value for immediate check after init

        // Case 2: Repository initially has a value
        val initialUrl = "https://initial.com"
        apiEndpointUrlFlow.value = initialUrl
        val newViewModelWithValue = ApiEndpointSettingsViewModel(mockPreferencesRepository)
        assertEquals(initialUrl, newViewModelWithValue.apiEndpointUrl.value) // Using .value
    }
}
