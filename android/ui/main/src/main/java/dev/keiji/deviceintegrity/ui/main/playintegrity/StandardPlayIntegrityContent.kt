package dev.keiji.deviceintegrity.ui.main.playintegrity

import android.content.Intent
import android.util.Log
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider // Kept for now
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dev.keiji.deviceintegrity.ui.main.InfoItem
import dev.keiji.deviceintegrity.ui.main.InfoItemContent
import dev.keiji.deviceintegrity.ui.main.keyattestation.InfoItemFormatter
import dev.keiji.deviceintegrity.ui.theme.ButtonHeight
import kotlinx.coroutines.launch

@Composable
fun StandardPlayIntegrityContent(
    uiState: StandardPlayIntegrityUiState,
    onContentBindingChange: (String) -> Unit,
    onRequestToken: () -> Unit,
    onRequestVerify: () -> Unit,
    modifier: Modifier = Modifier
) {
    val scrollState = rememberScrollState()
    val coroutineScope = rememberCoroutineScope()
    val clipboardManager = LocalClipboardManager.current
    val context = LocalContext.current

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(16.dp)
            .imePadding(),
        horizontalAlignment = Alignment.Start,
        verticalArrangement = Arrangement.Top
    ) {
        Text(text = "Step 1. 検証に使うコンテンツを設定")
        Spacer(modifier = Modifier.height(8.dp))
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
        Spacer(modifier = Modifier.height(8.dp))
        Button(
            onClick = { onRequestToken() },
            enabled = uiState.isRequestTokenButtonEnabled,
            modifier = Modifier
                .fillMaxWidth()
                .height(ButtonHeight)
        ) {
            Text(text = "Request Integrity Token")
        }

        if (uiState.requestHashVisible) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(text = "requestHash: ${uiState.requestHashValue}")
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(text = "Step 3. トークンを検証")
        Spacer(modifier = Modifier.height(8.dp))
        Button(
            onClick = { onRequestVerify() },
            enabled = uiState.isVerifyTokenButtonEnabled,
            modifier = Modifier
                .fillMaxWidth()
                .height(ButtonHeight)
        ) {
            Text(text = "Request Verify Token")
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Progress Indicators
        if (uiState.progressValue > PlayIntegrityProgressConstants.NO_PROGRESS && uiState.progressValue < PlayIntegrityProgressConstants.FULL_PROGRESS) {
            LinearProgressIndicator(
                progress = { uiState.progressValue },
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(8.dp))
        } else if (uiState.progressValue == PlayIntegrityProgressConstants.INDETERMINATE_PROGRESS) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center
            ) {
                CircularProgressIndicator(modifier = Modifier.size(24.dp))
            }
            Spacer(modifier = Modifier.height(8.dp))
        }

        val statusToDisplay = if (uiState.errorMessages.isNotEmpty()) {
            "Error: ${uiState.errorMessages.joinToString("\n")}"
        } else {
            uiState.status
        }

        InfoItemContent(
            status = statusToDisplay,
            isVerifiedSuccessfully = uiState.resultInfoItems.isNotEmpty() && uiState.errorMessages.isEmpty() && statusToDisplay.contains("complete", ignoreCase = true) && !statusToDisplay.contains("Failed", ignoreCase = true),
            infoItems = uiState.resultInfoItems,
            deviceRecognitionVerdict = uiState.serverVerificationPayload?.deviceIntegrity?.deviceRecognitionVerdict ?: emptyList(),
            onCopyClick = {
                val textToCopy = InfoItemFormatter.formatInfoItems(uiState.resultInfoItems)
                clipboardManager.setText(AnnotatedString(textToCopy))
                Log.d("StandardPlayIntegrity", "Copied: $textToCopy")
            },
            onShareClick = {
                val textToShare = InfoItemFormatter.formatInfoItems(uiState.resultInfoItems)
                val sendIntent: Intent = Intent().apply {
                    action = Intent.ACTION_SEND
                    putExtra(Intent.EXTRA_TEXT, textToShare)
                    type = "text/plain"
                }
                val shareIntent = Intent.createChooser(sendIntent, null)
                context.startActivity(shareIntent)
            }
        )
    }
}

@Preview
@Composable
private fun StandardPlayIntegrityContentPreview() {
    val sampleItems = listOf(
        InfoItem("Session ID (Current)", "preview-session-id-standard", indentLevel = 0),
        InfoItem("Request Hash (Calculated by Client)", "client-calculated-hash", indentLevel = 0),
        InfoItem("Play Integrity API Response", "", isHeader = true, indentLevel = 0),
        InfoItem("Request Details", "", isHeader = true, indentLevel = 1),
        InfoItem("Request Package Name", "dev.keiji.preview.standard", indentLevel = 2),
        InfoItem("Request Hash (from Server Response)", "preview-request-hash-standard", indentLevel = 2),
    )
    StandardPlayIntegrityContent(
        uiState = StandardPlayIntegrityUiState(
            contentBinding = "preview-content-binding",
            integrityToken = "preview-token",
            progressValue = 0.0F,
            status = "Preview status text for Standard.",
            resultInfoItems = sampleItems,
            currentSessionId = "preview-session-standard",
            requestHashValue = "client-calculated-hash-preview",
            serverVerificationPayload = null
        ),
        onContentBindingChange = {},
        onRequestToken = {},
        onRequestVerify = {}
    )
}
