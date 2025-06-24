package dev.keiji.deviceintegrity.api_endpoint_settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ApiEndpointSettingsScreen(
    modifier: Modifier = Modifier,
    uiState: ApiEndpointSettingsUiState,
    onEditingPlayIntegrityUrlChange: (String) -> Unit,
    onEditingKeyAttestationUrlChange: (String) -> Unit,
    onSaveClick: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("API Endpoint Settings") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.primary,
                )
            )
        }
    ) { innerPadding ->
        Column(
            modifier = modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(16.dp),
            // horizontalAlignment = Alignment.CenterHorizontally, // Remove to align left
            verticalArrangement = Arrangement.Top // Changed from Center to Top
        ) {
            Text(
                text = "Play Integrity APIを検証するサーバー",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.fillMaxWidth() // Align text to the start
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = uiState.editingPlayIntegrityUrl,
                onValueChange = { newText ->
                    onEditingPlayIntegrityUrlChange(newText)
                },
                // label = { Text("Enter URL") }, // Removed as per requirement
                singleLine = true,
                isError = uiState.errorMessage != null, // Assuming single error message for now
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = "Key Attestationを検証するサーバー",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.fillMaxWidth() // Align text to the start
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = uiState.editingKeyAttestationUrl,
                onValueChange = { newText ->
                    onEditingKeyAttestationUrlChange(newText)
                },
                singleLine = true,
                isError = uiState.errorMessage != null, // Assuming single error message for now
                modifier = Modifier.fillMaxWidth()
            )

            if (uiState.errorMessage != null) {
                Text(
                    text = uiState.errorMessage,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(start = 16.dp)
                )
            }
            Spacer(modifier = Modifier.height(16.dp))

            if (uiState.isLoading) {
                CircularProgressIndicator()
                Spacer(modifier = Modifier.height(16.dp))
            }

            Button(
                onClick = { onSaveClick() },
                enabled = !uiState.isLoading,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Save")
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
private fun ApiEndpointSettingsScreenPreview() {
    DeviceIntegrityTheme {
        Surface {
            ApiEndpointSettingsScreen(
                uiState = ApiEndpointSettingsUiState(
                    currentPlayIntegrityUrl = "https://example.com/api/play",
                    editingPlayIntegrityUrl = "https://example.com/api/play/edit",
                    currentKeyAttestationUrl = "https://example.com/api/key",
                    editingKeyAttestationUrl = "https://example.com/api/key/edit",
                    errorMessage = null,
                    isLoading = false,
                    saveSuccess = false
                ),
                onEditingPlayIntegrityUrlChange = {},
                onEditingKeyAttestationUrlChange = {},
                onSaveClick = {}
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
private fun ApiEndpointSettingsScreenWithErrorPreview() {
    DeviceIntegrityTheme {
        Surface {
            ApiEndpointSettingsScreen(
                uiState = ApiEndpointSettingsUiState(
                    currentPlayIntegrityUrl = "https://example.com/api/play",
                    editingPlayIntegrityUrl = "invalid url",
                    currentKeyAttestationUrl = "https://example.com/api/key",
                    editingKeyAttestationUrl = "invalid url",
                    errorMessage = "Invalid URL format",
                    isLoading = false,
                    saveSuccess = false
                ),
                onEditingPlayIntegrityUrlChange = {},
                onEditingKeyAttestationUrlChange = {},
                onSaveClick = {}
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
private fun ApiEndpointSettingsScreenLoadingPreview() {
    DeviceIntegrityTheme {
        Surface {
            ApiEndpointSettingsScreen(
                uiState = ApiEndpointSettingsUiState(
                    currentPlayIntegrityUrl = "https://example.com/api/play",
                    editingPlayIntegrityUrl = "https://example.com/api/play/loading",
                    currentKeyAttestationUrl = "https://example.com/api/key",
                    editingKeyAttestationUrl = "https://example.com/api/key/loading",
                    errorMessage = null,
                    isLoading = true,
                    saveSuccess = false
                ),
                onEditingPlayIntegrityUrlChange = {},
                onEditingKeyAttestationUrlChange = {},
                onSaveClick = {}
            )
        }
    }
}
