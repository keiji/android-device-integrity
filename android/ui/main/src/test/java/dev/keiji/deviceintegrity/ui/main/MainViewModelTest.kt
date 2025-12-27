package dev.keiji.deviceintegrity.ui.main

import androidx.lifecycle.SavedStateHandle
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider
import dev.keiji.deviceintegrity.repository.contract.PreferencesRepository
import dev.keiji.deviceintegrity.ui.nav.contract.AppScreen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.Mockito.anyLong
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.mockito.junit.MockitoJUnitRunner

@ExperimentalCoroutinesApi
@RunWith(MockitoJUnitRunner::class)
class MainViewModelTest {

    @Mock
    private lateinit var preferencesRepository: PreferencesRepository

    @Mock
    private lateinit var deviceInfoProvider: DeviceInfoProvider

    private lateinit var savedStateHandle: SavedStateHandle

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        savedStateHandle = SavedStateHandle()
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `init should save first launch datetime if not present`() = runTest {
        `when`(preferencesRepository.firstLaunchDatetime).thenReturn(flowOf(null))
        `when`(deviceInfoProvider.isKeyAttestationAvailable).thenReturn(true)

        val viewModel = MainViewModel(savedStateHandle, preferencesRepository, deviceInfoProvider)
        testDispatcher.scheduler.advanceUntilIdle()

        verify(preferencesRepository).saveFirstLaunchDatetime(anyLong())
    }

    @Test
    fun `init should NOT save first launch datetime if already present`() = runTest {
        `when`(preferencesRepository.firstLaunchDatetime).thenReturn(flowOf(123456789L))
        `when`(deviceInfoProvider.isKeyAttestationAvailable).thenReturn(true)

        val viewModel = MainViewModel(savedStateHandle, preferencesRepository, deviceInfoProvider)
        testDispatcher.scheduler.advanceUntilIdle()

        verify(preferencesRepository, never()).saveFirstLaunchDatetime(anyLong())
    }

    @Test
    fun `uiState should contain correct bottom navigation items`() = runTest {
        `when`(preferencesRepository.firstLaunchDatetime).thenReturn(flowOf(null))
        `when`(deviceInfoProvider.isKeyAttestationAvailable).thenReturn(true)

        val viewModel = MainViewModel(savedStateHandle, preferencesRepository, deviceInfoProvider)
        testDispatcher.scheduler.advanceUntilIdle()

        val uiState = viewModel.uiState.value
        assertEquals(3, uiState.bottomNavigationItems.size)
        assertTrue(uiState.isKeyAttestationSupported)
    }

    @Test
    fun `uiState should reflect key attestation support`() = runTest {
        `when`(preferencesRepository.firstLaunchDatetime).thenReturn(flowOf(null))
        `when`(deviceInfoProvider.isKeyAttestationAvailable).thenReturn(false)

        val viewModel = MainViewModel(savedStateHandle, preferencesRepository, deviceInfoProvider)
        testDispatcher.scheduler.advanceUntilIdle()

        val uiState = viewModel.uiState.value
        assertFalse(uiState.isKeyAttestationSupported)
    }

    @Test
    fun `setAgreed should update savedStateHandle`() = runTest {
        `when`(preferencesRepository.firstLaunchDatetime).thenReturn(flowOf(null))
        `when`(deviceInfoProvider.isKeyAttestationAvailable).thenReturn(true)

        val viewModel = MainViewModel(savedStateHandle, preferencesRepository, deviceInfoProvider)
        testDispatcher.scheduler.advanceUntilIdle()

        viewModel.setAgreed(true)
        assertTrue(viewModel.isAgreed.value)

        viewModel.setAgreed(false)
        assertFalse(viewModel.isAgreed.value)
    }
}
