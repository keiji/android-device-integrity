package dev.keiji.deviceintegrity.ui.main

import android.os.Build
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.repository.contract.PreferencesRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class MainViewModel @Inject constructor(
    private val savedStateHandle: SavedStateHandle,
    private val preferencesRepository: PreferencesRepository
) : ViewModel() {

    companion object {
        private const val KEY_IS_AGREED = "key_is_agreed"
    }

    val isAgreed: StateFlow<Boolean> = savedStateHandle.getStateFlow(KEY_IS_AGREED, false)

    private val _uiState = MutableStateFlow(MainUiState())
    val uiState: StateFlow<MainUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            val firstLaunch = preferencesRepository.firstLaunchDatetime.firstOrNull()
            if (firstLaunch == null) {
                preferencesRepository.saveFirstLaunchDatetime(System.currentTimeMillis())
            }
        }

        val availableScreens = listOf(
            AppScreen.PlayIntegrity,
            AppScreen.KeyAttestation,
            AppScreen.Menu
        )
        _uiState.value = MainUiState(bottomNavigationItems = availableScreens)
    }

    fun setAgreed(agreed: Boolean) {
        savedStateHandle[KEY_IS_AGREED] = agreed
    }
}
