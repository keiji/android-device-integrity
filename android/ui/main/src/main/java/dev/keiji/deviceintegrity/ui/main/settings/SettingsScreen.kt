package dev.keiji.deviceintegrity.ui.main.settings

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.keiji.deviceintegrity.ui.nav.contract.ApiEndpointSettingsNavigator
import dagger.hilt.android.EntryPointAccessors

@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel = viewModel()
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    val apiEndpointSettingsNavigator = EntryPointAccessors.fromActivity(
        context as android.app.Activity,
        MainHiltEntryPoint::class.java
    ).getApiEndpointSettingsNavigator()

    val settingsLauncher = rememberLauncherForActivityResult(
        contract = apiEndpointSettingsNavigator.contract(),
        onResult = { }
    )

    SettingsContent(
        uiState = uiState,
        onNavigateToApiEndpointSettings = {
            settingsLauncher.launch(Unit)
        }
    )
}

@Composable
private fun SettingsContent(
    uiState: SettingsUiState,
    onNavigateToApiEndpointSettings: () -> Unit
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

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = onNavigateToApiEndpointSettings,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("API Endpoint Settings")
        }
    }
}

@Preview
@Composable
private fun SettingsScreenPreview() {
    // Preview uses a default SettingsUiState which will have empty strings
    // For a more representative preview, you could mock the ViewModel or pass a sample UiState
    SettingsContent(
        uiState = SettingsUiState("1.0.0", 1, "13", "2023-08-01"),
        onNavigateToApiEndpointSettings = {}
    )
}
