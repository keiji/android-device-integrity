package dev.keiji.deviceintegrity.ui.main.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel

@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel = viewModel()
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    SettingsContent(uiState = uiState)
}

@Composable
private fun SettingsContent(
    uiState: SettingsUiState
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(
            text = "App Version Name: ${uiState.appVersionName}",
            style = MaterialTheme.typography.bodyLarge
        )
        Text(
            text = "App Version Code: ${uiState.appVersionCode}",
            style = MaterialTheme.typography.bodyLarge
        )
        Text(
            text = "OS Version: ${uiState.osVersion}",
            style = MaterialTheme.typography.bodyLarge
        )
        Text(
            text = "Security Patch Level: ${uiState.securityPatchLevel}",
            style = MaterialTheme.typography.bodyLarge
        )
    }
}

@Preview
@Composable
private fun SettingsScreenPreview() {
    // Preview uses a default SettingsUiState which will have empty strings
    // For a more representative preview, you could mock the ViewModel or pass a sample UiState
    SettingsContent(uiState = SettingsUiState("1.0.0", 1, "13", "2023-08-01"))
}
