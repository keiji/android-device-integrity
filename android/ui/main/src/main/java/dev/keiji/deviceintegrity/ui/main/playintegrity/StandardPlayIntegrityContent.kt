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
        Text(text = "Step 1. 検証に使うコンテンツを設定")
        OutlinedTextField(
            value = uiState.contentBinding,
            onValueChange = { onContentBindingChange(it) },
            label = { Text("Content") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = false,
            maxLines = 5
        )

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
private fun StandardPlayIntegrityContentPreview() {
    StandardPlayIntegrityContent(
        uiState = StandardPlayIntegrityUiState(
            contentBinding = "preview-content-binding",
            integrityToken = "preview-token",
            isLoading = false,
            status = "Preview status text for Standard."
            // isRequestTokenButtonEnabled and isVerifyTokenButtonEnabled are now calculated properties
        ),
        onContentBindingChange = {},
        onRequestToken = {},
        onRequestVerify = {}
    )
}
