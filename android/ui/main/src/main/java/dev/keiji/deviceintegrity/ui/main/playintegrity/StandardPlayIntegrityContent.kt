package dev.keiji.deviceintegrity.ui.main.playintegrity

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp

@Composable
fun StandardPlayIntegrityContent(
    uiState: StandardPlayIntegrityUiState,
    onContentBindingChange: (String) -> Unit,
    onRequestToken: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(text = "Play Integrity Token Requester (Standard)") // Title updated

        Spacer(modifier = Modifier.height(16.dp))

        OutlinedTextField(
            value = uiState.contentBinding,
            onValueChange = { onContentBindingChange(it) },
            label = { Text("Content Binding (requestHash)") }, // Label updated
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = { onRequestToken() },
            enabled = !uiState.isLoading,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(text = "Request Integrity Token")
        }

        Spacer(modifier = Modifier.height(16.dp))

        if (uiState.isLoading) {
            CircularProgressIndicator()
        } else {
            Text(text = uiState.result)
        }
    }
}

@Preview
@Composable
private fun StandardPlayIntegrityContentPreview() {
    StandardPlayIntegrityContent(
        uiState = StandardPlayIntegrityUiState(
            contentBinding = "preview-content-binding",
            isLoading = true, // Changed to true for variety in preview
            result = "Preview result text for Standard."
        ),
        onContentBindingChange = {},
        onRequestToken = {}
    )
}
