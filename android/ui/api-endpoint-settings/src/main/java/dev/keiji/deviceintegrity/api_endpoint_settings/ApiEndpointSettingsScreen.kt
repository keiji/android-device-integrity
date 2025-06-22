package dev.keiji.deviceintegrity.api_endpoint_settings

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme
import java.net.MalformedURLException
import java.net.URL

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ApiEndpointSettingsScreen(
    modifier: Modifier = Modifier,
) {
    var text by remember { mutableStateOf("") }
    var errorText by remember { mutableStateOf<String?>(null) }

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
                .padding(innerPadding) // Apply innerPadding from Scaffold
                .padding(16.dp), // Additional padding for content
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = "API Endpoint URL",
                style = MaterialTheme.typography.titleMedium
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = text,
                onValueChange = { newText ->
                    // Allow only URL-safe characters
                    if (newText.all { it.isLetterOrDigit() || it in ":/?#[]@!$&'()*+,;=-_.~%" }) {
                        text = newText
                        errorText = null // Clear error when user types
                    }
                },
                label = { Text("Enter URL") },
                singleLine = true,
                isError = errorText != null,
                modifier = Modifier.fillMaxWidth()
            )
            if (errorText != null) {
                Text(
                    text = errorText!!,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(start = 16.dp)
                )
            }
            Spacer(modifier = Modifier.height(16.dp))
            Button(
                onClick = {
                    try {
                        URL(text) // Validate URL
                        // TODO: Implement persistence logic
                        errorText = null // Clear error on success
                    } catch (e: MalformedURLException) {
                        errorText = "Invalid URL format"
                    }
                },
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
        Surface { // Surface is still good for previews of screen content
            ApiEndpointSettingsScreen()
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Preview(showBackground = true)
@Composable
private fun ApiEndpointSettingsScreenWithErrorPreview() {
    DeviceIntegrityTheme {
        Surface {
            // Replicating the state for error preview within the Scaffold structure
            var text by remember { mutableStateOf("invalid url") }
            var errorText by remember { mutableStateOf<String?>("Invalid URL format") }

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
                    modifier = Modifier
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
                        value = text,
                        onValueChange = { newText ->
                            if (newText.all { it.isLetterOrDigit() || it in ":/?#[]@!$&'()*+,;=-_.~%" }) {
                                text = newText
                                errorText = null
                            }
                        },
                        label = { Text("Enter URL") },
                        singleLine = true,
                        isError = errorText != null,
                        modifier = Modifier.fillMaxWidth()
                    )
                    if (errorText != null) {
                        Text(
                            text = errorText!!,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(start = 16.dp)
                        )
                    }
                    Spacer(modifier = Modifier.height(16.dp))
                    Button(
                        onClick = {
                            try {
                                URL(text)
                                errorText = null
                                // TODO: Implement persistence logic
                            } catch (e: MalformedURLException) {
                                errorText = "Invalid URL format"
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Save")
                    }
                }
            }
        }
    }
}
