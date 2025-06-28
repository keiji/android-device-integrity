package dev.keiji.deviceintegrity.ui.main.playintegrity

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
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
    val scrollState = rememberScrollState()

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(16.dp)
            .imePadding(),
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
            playIntegrityResponse = uiState.playIntegrityResponse,
            deviceInfo = uiState.deviceInfo,
            securityInfo = uiState.securityInfo,
            currentSessionId = uiState.currentSessionId
        )
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
            status = "Preview status text for Classic.",
            playIntegrityResponse = dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal(
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
                    deviceAttributes = dev.keiji.deviceintegrity.api.playintegrity.DeviceAttributes(
                        sdkVersion = 30
                    ),
                    recentDeviceActivity = dev.keiji.deviceintegrity.api.playintegrity.RecentDeviceActivity(
                        deviceActivityLevel = "LEVEL_1"
                    )
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
            ),
            // Preview with dummy DeviceInfo and SecurityInfo
            deviceInfo = dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo(
                brand = "PreviewBrand",
                model = "PreviewModel",
                device = "PreviewDevice",
                product = "PreviewProduct",
                manufacturer = "PreviewManufacturer",
                hardware = "PreviewHardware",
                board = "PreviewBoard",
                bootloader = "PreviewBootloader",
                versionRelease = "12",
                sdkInt = 31,
                fingerprint = "PreviewFingerprint",
                securityPatch = "2023-03-05"
            ),
            securityInfo = dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo(
                isDeviceLockEnabled = true, isBiometricsEnabled = false,
                hasClass3Authenticator = true, hasStrongbox = false
            )
        ),
        onFetchNonce = {},
        onRequestToken = {},
        onRequestVerify = {}
    )
}
