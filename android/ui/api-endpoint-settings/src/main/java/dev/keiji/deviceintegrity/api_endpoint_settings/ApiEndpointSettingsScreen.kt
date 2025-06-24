package dev.keiji.deviceintegrity.api_endpoint_settings

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
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
    onEditingUrlChange: (String) -> Unit,
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
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = "API Endpoint URL",
                style = MaterialTheme.typography.titleMedium
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = uiState.editingUrl,
                onValueChange = { newText ->
                    // Basic filtering for typical URL characters (Screen can do minimal, ViewModel does full validation)
                    // if (newText.all { it.isLetterOrDigit() || it in ":/?#[]@!$&'()*+,;=-_.~%" }) {
                    onEditingUrlChange(newText)
                    // }
                },
                label = { Text("Enter URL") },
                singleLine = true,
                isError = uiState.errorMessage != null,
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
                    currentUrl = "https://example.com/api",
                    editingUrl = "https://example.com/api/edit",
                    errorMessage = null,
                    isLoading = false,
                    saveSuccess = false
                ),
                onEditingUrlChange = {},
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
                    currentUrl = "https://example.com/api",
                    editingUrl = "invalid url",
                    errorMessage = "Invalid URL format",
                    isLoading = false,
                    saveSuccess = false
                ),
                onEditingUrlChange = {},
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
                    currentUrl = "https://example.com/api",
                    editingUrl = "https://example.com/api/loading",
                    errorMessage = null,
                    isLoading = true,
                    saveSuccess = false
                ),
                onEditingUrlChange = {},
                onSaveClick = {}
            )
        }
    }
}
