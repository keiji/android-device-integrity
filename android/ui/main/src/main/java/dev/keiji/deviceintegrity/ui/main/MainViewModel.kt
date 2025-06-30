package dev.keiji.deviceintegrity.ui.main

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.StateFlow
import javax.inject.Inject

@HiltViewModel
class MainViewModel @Inject constructor(
    private val savedStateHandle: SavedStateHandle
) : ViewModel() {

    companion object {
        private const val KEY_IS_AGREED = "key_is_agreed"
    }

    val isAgreed: StateFlow<Boolean> = savedStateHandle.getStateFlow(KEY_IS_AGREED, false)

    fun setAgreed(agreed: Boolean) {
        savedStateHandle[KEY_IS_AGREED] = agreed
    }
}
