package dev.keiji.deviceintegrity.ui.agreement

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.provider.contract.UrlProvider
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed class UiEvent {
    data class OpenPrivacyPolicy(val url: String) : UiEvent()
}

@HiltViewModel
class AgreementViewModel @Inject constructor(
    private val urlProvider: UrlProvider
) : ViewModel() {

    private val _eventChannel = Channel<UiEvent>()
    val eventFlow = _eventChannel.receiveAsFlow()

    fun openPrivacyPolicy() {
        viewModelScope.launch {
            _eventChannel.send(UiEvent.OpenPrivacyPolicy(urlProvider.privacyPolicyUrl))
        }
    }
}
