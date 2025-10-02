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
import androidx.compose.material3.HorizontalDivider // Kept for now, though not directly used by InfoItemContent
import androidx.compose.material3.LinearProgressIndicator
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
import dev.keiji.deviceintegrity.ui.playintegrity.R
import dev.keiji.deviceintegrity.ui.theme.ButtonHeight
import dev.keiji.deviceintegrity.ui.common.ProgressConstants
import kotlinx.coroutines.launch

@Composable
fun ClassicPlayIntegrityContent(
    uiState: ClassicPlayIntegrityUiState,
    onFetchNonce: () -> Unit,
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
        Text(text = stringResource(id = R.string.classic_pi_title_step1))
        Spacer(modifier = Modifier.height(12.dp))
        Button(
            onClick = { onFetchNonce() },
            enabled = uiState.isFetchNonceButtonEnabled,
            modifier = Modifier
                .fillMaxWidth()
                .height(ButtonHeight)
        ) {
            Text(text = stringResource(id = R.string.classic_pi_button_fetch_nonce))
        }
        if (uiState.nonce.isNotEmpty()) {
            Text(text = stringResource(id = R.string.classic_pi_label_nonce, uiState.nonce))
        }

        Spacer(modifier = Modifier.height(24.dp))
        Text(text = stringResource(id = R.string.classic_pi_title_step2))
        Spacer(modifier = Modifier.height(12.dp))
        Button(
            onClick = { onRequestToken() },
            enabled = uiState.isRequestTokenButtonEnabled,
            modifier = Modifier
                .fillMaxWidth()
                .height(ButtonHeight)
        ) {
            Text(text = stringResource(id = R.string.classic_pi_button_request_integrity_token))
        }

        Spacer(modifier = Modifier.height(24.dp))
        Text(text = stringResource(id = R.string.classic_pi_title_step3))
        Spacer(modifier = Modifier.height(12.dp))
        Button(
            onClick = { onRequestVerify() },
            enabled = uiState.isVerifyTokenButtonEnabled,
            modifier = Modifier
                .fillMaxWidth()
                .height(ButtonHeight)
        ) {
            Text(text = stringResource(id = R.string.classic_pi_button_request_verify_token))
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
            stringResource(id = R.string.classic_pi_label_error, uiState.errorMessages.joinToString("\n"))
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
                Log.d("ClassicPlayIntegrity", "Copied: $textToCopy")
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
private fun ClassicPlayIntegrityContentPreview() {
    val sampleItems = listOf(
        InfoItem("Session ID (Current)", "preview-session-id-classic", indentLevel = 0),
        InfoItem("Play Integrity API Response", "", isHeader = true, indentLevel = 0),
        InfoItem("Request Details", "", isHeader = true, indentLevel = 1),
        InfoItem("Request Package Name", "dev.keiji.preview", indentLevel = 2),
        InfoItem("Nonce", "preview-nonce-from-server", indentLevel = 2),
    )
    ClassicPlayIntegrityContent(
        uiState = ClassicPlayIntegrityUiState(
            nonce = "preview-nonce",
            integrityToken = "preview-token",
            progressValue = 0.0F,
            status = "Preview status text for Classic.",
            resultInfoItems = sampleItems,
            currentSessionId = "preview-session-classic",
            serverVerificationPayload = null
        ),
        onFetchNonce = {},
        onRequestToken = {},
        onRequestVerify = {}
    )
}
