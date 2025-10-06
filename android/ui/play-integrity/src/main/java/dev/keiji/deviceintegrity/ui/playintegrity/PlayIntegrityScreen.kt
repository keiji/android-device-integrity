package dev.keiji.deviceintegrity.ui.playintegrity

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview

enum class PlayIntegrityTab {
    Standard, Classic
}

@Composable
fun PlayIntegrityScreen(
    modifier: Modifier = Modifier,
    classicUiState: ClassicPlayIntegrityUiState,
    standardUiState: StandardPlayIntegrityUiState,
    onClassicFetchNonce: () -> Unit,
    onClassicRequestToken: () -> Unit,
    onClassicRequestVerify: () -> Unit,
    onStandardContentBindingChange: (String) -> Unit,
    onStandardRequestToken: () -> Unit,
    onStandardRequestVerify: () -> Unit,
) {
    var selectedTab by remember { mutableStateOf(PlayIntegrityTab.Standard) }
    // val classicUiState by classicViewModel.uiState.collectAsState() // Removed
    // val standardUiState by standardViewModel.uiState.collectAsState() // Removed

    Column(modifier = modifier.fillMaxSize()) {
        TabRow(selectedTabIndex = selectedTab.ordinal) {
            PlayIntegrityTab.entries.forEach { tab ->
                Tab(
                    selected = selectedTab == tab,
                    onClick = { selectedTab = tab },
                    text = { Text(tab.name) }
                )
            }
        }

        when (selectedTab) {
            PlayIntegrityTab.Classic -> {
                ClassicPlayIntegrityContent(
                    uiState = classicUiState,
                    onFetchNonce = onClassicFetchNonce,
                    onRequestToken = onClassicRequestToken,
                    onRequestVerify = onClassicRequestVerify
                )
            }

            PlayIntegrityTab.Standard -> {
                StandardPlayIntegrityContent(
                    uiState = standardUiState,
                    onContentBindingChange = onStandardContentBindingChange,
                    onRequestToken = onStandardRequestToken,
                    onRequestVerify = onStandardRequestVerify
                )
            }
        }
    }
}

@Preview
@Composable
private fun PlayIntegrityScreenPreview_ClassicSelected() {
    PlayIntegrityScreen(
        classicUiState = ClassicPlayIntegrityUiState(
            nonce = "preview-nonce",
            integrityToken = "preview-token",
            progressValue = 0.0F,
            status = "Preview result text for Classic."
        ),
        standardUiState = StandardPlayIntegrityUiState(),
        onClassicFetchNonce = {},
        onClassicRequestToken = {},
        onClassicRequestVerify = {},
        onStandardContentBindingChange = {},
        onStandardRequestToken = {},
        onStandardRequestVerify = {}
    )
}

@Preview
@Composable
private fun PlayIntegrityScreenPreview_StandardSelected() {
    // To preview the Standard tab selected, we need to simulate the tab selection
    // or adjust the PlayIntegrityScreen to allow initial tab selection for preview.
    // For now, this will render with Classic as default then allow interaction to Standard.
    // A more direct preview of Standard tab would require PlayIntegrityScreen to accept
    // an initialSelectedTab parameter or similar.
    PlayIntegrityScreen(
        classicUiState = ClassicPlayIntegrityUiState(),
        standardUiState = StandardPlayIntegrityUiState(
            contentBinding = "preview-content",
            integrityToken = "preview-token",
            progressValue = 0.0F,
            status = "Preview Standard Content"
        ),
        onClassicFetchNonce = {},
        onClassicRequestToken = {},
        onClassicRequestVerify = {},
        onStandardContentBindingChange = {},
        onStandardRequestToken = {},
        onStandardRequestVerify = {}
    )
    // To truly preview the standard tab selected by default, one might:
    // 1. Modify PlayIntegrityScreen to accept an `initialSelectedTab: PlayIntegrityTab`
    // 2. Create a wrapper Composable for preview that manages the selectedTab state and
    //    calls PlayIntegrityScreen, setting the initial tab to Standard.
    // For this refactoring, simply providing the necessary states and callbacks is sufficient.
}
