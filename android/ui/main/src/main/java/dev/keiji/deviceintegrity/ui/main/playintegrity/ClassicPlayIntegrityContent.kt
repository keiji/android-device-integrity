package dev.keiji.deviceintegrity.ui.main.playintegrity

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
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
    val scrollState = rememberScrollState()

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
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

        StatusDisplayArea(
            isLoading = uiState.isLoading,
            errorMessages = uiState.errorMessages,
            statusText = uiState.status,
            tokenPayload = uiState.verifyTokenResponse?.tokenPayloadExternal
        )
    }
}

// Preview remains, but the actual composables DisplayTokenResponse and formatTokenPayload are now in PlayIntegrityStatusComposables.kt
@Preview
@Composable
private fun ClassicPlayIntegrityContentPreview() {
    ClassicPlayIntegrityContent(
        uiState = ClassicPlayIntegrityUiState(
            nonce = "preview-nonce",
            integrityToken = "preview-token",
            isLoading = false,
            status = "Preview status text for Classic.",
            verifyTokenResponse = dev.keiji.deviceintegrity.api.playintegrity.VerifyTokenResponse(
                tokenPayloadExternal = dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal(
                    requestDetails = dev.keiji.deviceintegrity.api.playintegrity.RequestDetails(
                        requestPackageName = "dev.keiji.preview",
                        nonce = "preview-nonce-from-server",
                        requestHash = "preview-request-hash",
                        timestampMillis = System.currentTimeMillis()
                    ),
                    appIntegrity = dev.keiji.deviceintegrity.api.playintegrity.AppIntegrity(
                        appRecognitionVerdict = "MEETS_DEVICE_INTEGRITY",
                        packageName = "dev.keiji.preview",
                        certificateSha256Digest = listOf("cert1", "cert2"),
                        versionCode = 123
                    ),
                    deviceIntegrity = dev.keiji.deviceintegrity.api.playintegrity.DeviceIntegrity(
                        deviceRecognitionVerdict = listOf("MEETS_DEVICE_INTEGRITY"),
                        deviceAttributes = dev.keiji.deviceintegrity.api.playintegrity.DeviceAttributes(sdkVersion = 30),
                        recentDeviceActivity = dev.keiji.deviceintegrity.api.playintegrity.RecentDeviceActivity(deviceActivityLevel = "LEVEL_1")
                    ),
                    accountDetails = dev.keiji.deviceintegrity.api.playintegrity.AccountDetails(
                        appLicensingVerdict = "LICENSED"
                    ),
                    environmentDetails = dev.keiji.deviceintegrity.api.playintegrity.EnvironmentDetails(
                        appAccessRiskVerdict = dev.keiji.deviceintegrity.api.playintegrity.AppAccessRiskVerdict(
                            appsDetected = listOf("app1", "app2")
                        ),
                        playProtectVerdict = "NO_ISSUES"
                    )
                )
            )
        ),
        onFetchNonce = {},
        onRequestToken = {},
        onRequestVerify = {}
    )
}
