package dev.keiji.deviceintegrity.ui.main.playintegrity

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.hilt.navigation.compose.hiltViewModel

enum class PlayIntegrityTab {
    Classic, Standard
}

@Composable
fun PlayIntegrityScreen(
    modifier: Modifier = Modifier,
    classicViewModel: ClassicPlayIntegrityViewModel = hiltViewModel(),
    standardViewModel: StandardPlayIntegrityViewModel = hiltViewModel(),
) {
    var selectedTab by remember { mutableStateOf(PlayIntegrityTab.Classic) }
    val classicUiState by classicViewModel.uiState.collectAsState()
    val standardUiState by standardViewModel.uiState.collectAsState()

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
                    onNonceChange = { classicViewModel.updateNonce(it) },
                    onRequestToken = { classicViewModel.fetchIntegrityToken() },
                    onRequestVerify = { classicViewModel.verifyToken() }
                )
            }

            PlayIntegrityTab.Standard -> {
                StandardPlayIntegrityContent(
                    uiState = standardUiState,
                    onContentBindingChange = { standardViewModel.updateContentBinding(it) },
                    onRequestToken = { standardViewModel.fetchIntegrityToken() },
                    onRequestVerify = { standardViewModel.verifyToken() }
                )
            }
        }
    }
}

@Preview
@Composable
private fun PlayIntegrityScreenPreview_ClassicSelected() {
    // This preview will be basic as ViewModels are hard to mock directly in Preview
    // without significant extra setup. It will show the tab structure.
    var selectedTab by remember { mutableStateOf(PlayIntegrityTab.Classic) }

    Column(modifier = Modifier.fillMaxSize()) {
        TabRow(selectedTabIndex = selectedTab.ordinal) {
            PlayIntegrityTab.entries.forEach { tab ->
                Tab(
                    selected = selectedTab == tab,
                    onClick = { selectedTab = tab },
                    text = { Text(tab.name) }
                )
            }
        }
        // For preview, we can show one of the contents directly or a placeholder
        ClassicPlayIntegrityContent(
            uiState = ClassicPlayIntegrityUiState(
                nonce = "preview-nonce",
                isLoading = false,
                result = "Preview Classic Content"
            ),
            onNonceChange = {},
            onRequestToken = {},
            onRequestVerify = {}
        )
    }
}

@Preview
@Composable
private fun PlayIntegrityScreenPreview_StandardSelected() {
    var selectedTab by remember { mutableStateOf(PlayIntegrityTab.Standard) }

    Column(modifier = Modifier.fillMaxSize()) {
        TabRow(selectedTabIndex = selectedTab.ordinal) {
            PlayIntegrityTab.entries.forEach { tab ->
                Tab(
                    selected = selectedTab == tab,
                    onClick = { selectedTab = tab },
                    text = { Text(tab.name) }
                )
            }
        }
        StandardPlayIntegrityContent(
            uiState = StandardPlayIntegrityUiState(
                contentBinding = "preview-content",
                isLoading = false,
                result = "Preview Standard Content"
            ),
            onContentBindingChange = {},
            onRequestToken = {},
            onRequestVerify = {}
        )
    }
}
