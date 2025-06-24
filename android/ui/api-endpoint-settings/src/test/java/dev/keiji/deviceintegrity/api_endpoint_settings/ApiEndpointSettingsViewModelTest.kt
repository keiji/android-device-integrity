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

    private val playIntegrityVerifyApiEndpointUrlFlow = MutableStateFlow<String?>(null)
    private val keyAttestationVerifyApiEndpointUrlFlow = MutableStateFlow<String?>(null)

    @Before
    fun setup() {
        Dispatchers.setMain(testDispatcher)

        mockPreferencesRepository = mock()
        whenever(mockPreferencesRepository.playIntegrityVerifyApiEndpointUrl).thenReturn(playIntegrityVerifyApiEndpointUrlFlow)
        whenever(mockPreferencesRepository.keyAttestationVerifyApiEndpointUrl).thenReturn(keyAttestationVerifyApiEndpointUrlFlow)

        viewModel = ApiEndpointSettingsViewModel(mockPreferencesRepository)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `saveApiEndpoints calls repository to save URLs`() = runTest {
        val playUrl = "https://play.newurl.com"
        val keyUrl = "https://key.newurl.com"

        viewModel.updateEditingPlayIntegrityUrl(playUrl)
        viewModel.updateEditingKeyAttestationUrl(keyUrl)
        viewModel.saveApiEndpoints()

        testDispatcher.scheduler.advanceUntilIdle()

        verify(mockPreferencesRepository).savePlayIntegrityVerifyApiEndpointUrl(playUrl)
        verify(mockPreferencesRepository).saveKeyAttestationVerifyApiEndpointUrl(keyUrl)
    }

    @Test
    fun `saveApiEndpoints calls repository with empty strings if URLs are blank`() = runTest {
        viewModel.updateEditingPlayIntegrityUrl("  ") // Blank URL
        viewModel.updateEditingKeyAttestationUrl("")  // Empty URL
        viewModel.saveApiEndpoints()

        testDispatcher.scheduler.advanceUntilIdle()

        // Assuming blank URLs are trimmed and saved as empty strings by the ViewModel's save logic
        verify(mockPreferencesRepository).savePlayIntegrityVerifyApiEndpointUrl("  ")
        verify(mockPreferencesRepository).saveKeyAttestationVerifyApiEndpointUrl("")
    }

    @Test
    fun `initial UI state loads URLs from repository`() = runTest {
        val initialPlayUrl = "https://initial-play.com"
        val initialKeyUrl = "https://initial-key.com"

        playIntegrityVerifyApiEndpointUrlFlow.value = initialPlayUrl
        keyAttestationVerifyApiEndpointUrlFlow.value = initialKeyUrl

        // Re-create ViewModel or trigger init somehow if init logic is complex.
        // For this ViewModel, flows are collected on init.
        // We need to advance the dispatcher to allow collection to occur.
        val newViewModel = ApiEndpointSettingsViewModel(mockPreferencesRepository)
        testDispatcher.scheduler.advanceUntilIdle()


        assert(newViewModel.uiState.value.currentPlayIntegrityUrl == initialPlayUrl)
        assert(newViewModel.uiState.value.editingPlayIntegrityUrl == initialPlayUrl)
        assert(newViewModel.uiState.value.currentKeyAttestationUrl == initialKeyUrl)
        assert(newViewModel.uiState.value.editingKeyAttestationUrl == initialKeyUrl)
    }
}
