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
fun ClassicPlayIntegrityContent(
    uiState: ClassicPlayIntegrityUiState,
    onNonceChange: (String) -> Unit,
    onRequestToken: () -> Unit,
    onRequestVerify: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Top
    ) {
        Text(text = "Step 1. サーバーからNonceを取得")
        OutlinedTextField(
            value = uiState.nonce,
            onValueChange = { onNonceChange(it) },
            label = { Text("Nonce") },
            modifier = Modifier.fillMaxWidth(),
            enabled = false
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(text = "Step 2. トークンを取得")
        Button(
            onClick = { onRequestToken() },
            enabled = !uiState.isLoading,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(text = "Request Integrity Token")
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(text = "Step 3. トークンを検証")
        Button(
            onClick = { onRequestVerify() },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(text = "Request Verify Token")
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
private fun ClassicPlayIntegrityContentPreview() {
    ClassicPlayIntegrityContent(
        uiState = ClassicPlayIntegrityUiState(
            nonce = "preview-nonce",
            isLoading = false,
            result = "Preview result text for Classic."
        ),
        onNonceChange = {},
        onRequestToken = {},
        onRequestVerify = {}
    )
}
