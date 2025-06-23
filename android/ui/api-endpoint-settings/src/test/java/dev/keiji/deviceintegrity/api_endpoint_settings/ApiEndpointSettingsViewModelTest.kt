package dev.keiji.deviceintegrity.api_endpoint_settings

import dev.keiji.deviceintegrity.repository.contract.PreferencesRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

@ExperimentalCoroutinesApi
class ApiEndpointSettingsViewModelTest {

    private val testDispatcher = StandardTestDispatcher()

    private lateinit var viewModel: ApiEndpointSettingsViewModel
    private lateinit var mockPreferencesRepository: PreferencesRepository

    private val apiEndpointUrlFlow = MutableStateFlow<String?>("ull")

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
    fun `saveApiEndpointUrl calls repository to save URL`() = runTest {
        val testUrl = "https.newurl.com"
        viewModel.saveApiEndpointUrl(testUrl)
        testDispatcher.scheduler.advanceUntilIdle() // Ensure coroutine launched by saveApiEndpointUrl completes
        verify(mockPreferencesRepository).saveApiEndpointUrl(testUrl)
    }
}
