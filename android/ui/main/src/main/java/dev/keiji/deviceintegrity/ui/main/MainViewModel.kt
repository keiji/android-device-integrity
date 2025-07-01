package dev.keiji.deviceintegrity.ui.main

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.repository.contract.PreferencesRepository
import kotlinx.coroutines.flow.StateFlow
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

    init {
        viewModelScope.launch {
            val firstLaunch = preferencesRepository.firstLaunchDatetime.firstOrNull()
            if (firstLaunch == null) {
                preferencesRepository.saveFirstLaunchDatetime(System.currentTimeMillis())
            }
        }
    }

    fun setAgreed(agreed: Boolean) {
        savedStateHandle[KEY_IS_AGREED] = agreed
    }
}
