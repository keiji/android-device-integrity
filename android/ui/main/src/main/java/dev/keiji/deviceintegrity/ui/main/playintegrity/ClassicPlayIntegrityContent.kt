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
import androidx.compose.material3.Divider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp

@Composable
fun ClassicPlayIntegrityContent(
    uiState: ClassicPlayIntegrityUiState,
    onFetchNonce: () -> Unit,
    onRequestToken: () -> Unit,
    onRequestVerify: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.Start, // Align labels to the left
        verticalArrangement = Arrangement.Top
    ) {
        Text(text = "Step 1. サーバーからNonceを取得")
        Button(
            onClick = { onFetchNonce() },
            enabled = uiState.isFetchNonceButtonEnabled,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(text = "Fetch Nonce")
        }
        if (uiState.nonce.isNotEmpty()) {
            Text(text = "Nonce: ${uiState.nonce}")
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(text = "Step 2. トークンを取得")
        Button(
            onClick = { onRequestToken() },
            enabled = uiState.isRequestTokenButtonEnabled,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(text = "Request Integrity Token")
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(text = "Step 3. トークンを検証")
        Button(
            onClick = { onRequestVerify() },
            enabled = uiState.isVerifyTokenButtonEnabled,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(text = "Request Verify Token")
        }

        Spacer(modifier = Modifier.height(16.dp))
        Divider() // Add a divider
        Spacer(modifier = Modifier.height(16.dp))

        if (uiState.isLoading) {
            CircularProgressIndicator(modifier = Modifier.align(Alignment.CenterHorizontally))
        } else {
            Text(text = uiState.status) // Display status text
        }
    }
}

@Preview
@Composable
private fun ClassicPlayIntegrityContentPreview() {
    ClassicPlayIntegrityContent(
        uiState = ClassicPlayIntegrityUiState(
            nonce = "preview-nonce",
            integrityToken = "preview-token",
            isLoading = false,
            status = "Preview status text for Classic."
            // isFetchNonceButtonEnabled, isRequestTokenButtonEnabled,
            // and isVerifyTokenButtonEnabled are now calculated properties
        ),
        onFetchNonce = {},
        onRequestToken = {},
        onRequestVerify = {}
    )
}
