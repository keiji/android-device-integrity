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
import androidx.compose.runtime.getValue
// import androidx.compose.runtime.mutableStateOf // No longer needed for nonce
// import androidx.compose.runtime.remember // No longer needed for nonce
// import androidx.compose.runtime.setValue // No longer needed for nonce
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp

@Composable
fun PlayIntegrityScreen(
    uiState: PlayIntegrityUiState,
    onNonceChange: (String) -> Unit,
    onRequestToken: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(text = "Play Integrity Token Requester")

        Spacer(modifier = Modifier.height(16.dp))

        OutlinedTextField(
            value = uiState.nonce, // Use nonce from uiState
            onValueChange = { onNonceChange(it) }, // Use callback
            label = { Text("Nonce") },
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = { onRequestToken() }, // Use callback
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
private fun PlayIntegrityScreenPreview() {
    PlayIntegrityScreen(
        uiState = PlayIntegrityUiState(
            nonce = "preview-nonce",
            isLoading = false,
            result = "Preview result text."
        ),
        onNonceChange = {},
        onRequestToken = {}
    )
}
