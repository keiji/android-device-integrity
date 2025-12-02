package dev.keiji.deviceintegrity.ui.playintegrity

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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dev.keiji.deviceintegrity.ui.common.InfoItem
import dev.keiji.deviceintegrity.ui.common.InfoItemContent
import dev.keiji.deviceintegrity.ui.common.InfoItemFormatter
import dev.keiji.deviceintegrity.ui.theme.ButtonHeight
import dev.keiji.deviceintegrity.ui.common.ProgressConstants
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
        Text(text = stringResource(id = R.string.standard_pi_title_step1))
        Spacer(modifier = Modifier.height(12.dp))
        OutlinedTextField(
            value = uiState.contentBinding,
            onValueChange = { onContentBindingChange(it) },
            label = { Text(stringResource(id = R.string.standard_pi_label_content)) },
            modifier = Modifier.fillMaxWidth(),
            singleLine = false,
            maxLines = 5
        )

        Spacer(modifier = Modifier.height(24.dp))
        Text(text = stringResource(id = R.string.standard_pi_title_step2))
        Spacer(modifier = Modifier.height(12.dp))
        Button(
            onClick = { onRequestToken() },
            enabled = uiState.isRequestTokenButtonEnabled,
            modifier = Modifier
                .fillMaxWidth()
                .height(ButtonHeight)
        ) {
            Text(text = stringResource(id = R.string.standard_pi_button_request_integrity_token))
        }

        if (uiState.requestHashVisible) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(text = stringResource(id = R.string.standard_pi_label_request_hash, uiState.requestHashValue))
        }

        Spacer(modifier = Modifier.height(24.dp))
        Text(text = stringResource(id = R.string.standard_pi_title_step3))
        Spacer(modifier = Modifier.height(12.dp))
        Button(
            onClick = { onRequestVerify() },
            enabled = uiState.isVerifyTokenButtonEnabled,
            modifier = Modifier
                .fillMaxWidth()
                .height(ButtonHeight)
        ) {
            Text(text = stringResource(id = R.string.standard_pi_button_request_verify_token))
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Progress Indicators
        val isProgressVisible =
            uiState.progressValue != ProgressConstants.NO_PROGRESS

        if (isProgressVisible) {
            val progress = if (uiState.progressValue == ProgressConstants.INDETERMINATE_PROGRESS) {
                null
            } else {
                uiState.progressValue
            }

            progress?.let {
                LinearProgressIndicator(
                    progress = { it },
                    modifier = Modifier.fillMaxWidth()
                )
            } ?: LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            Spacer(modifier = Modifier.height(8.dp))
        }

        val statusToDisplay = if (uiState.errorMessages.isNotEmpty()) {
            stringResource(id = R.string.standard_pi_label_error, uiState.errorMessages.joinToString("\n"))
        } else {
            uiState.status
        }

        InfoItemContent(
            status = statusToDisplay,
            isVerifiedSuccessfully = uiState.resultInfoItems.isNotEmpty() && uiState.errorMessages.isEmpty() && statusToDisplay.contains("complete", ignoreCase = true) && !statusToDisplay.contains("Failed", ignoreCase = true),
            infoItems = uiState.resultInfoItems,
            headContent = {
                uiState.serverVerificationPayload?.playIntegrityResponse?.tokenPayloadExternal?.deviceIntegrity?.deviceRecognitionVerdict?.let {
                    DeviceIntegrityResults(deviceRecognitionVerdict = it)
                }
            },
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
