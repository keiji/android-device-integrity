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

        if (uiState.requestHashVisible) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(text = "requestHash: ${uiState.requestHashValue}")
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
            progressValue = uiState.progressValue,
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
private fun StandardPlayIntegrityContentPreview() {
    StandardPlayIntegrityContent(
        uiState = StandardPlayIntegrityUiState(
            contentBinding = "preview-content-binding",
            integrityToken = "preview-token",
            progressValue = 0.0F,
            status = "Preview status text for Standard.",
            playIntegrityResponse = dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal(
                requestDetails = dev.keiji.deviceintegrity.api.playintegrity.RequestDetails(
                    requestPackageName = "dev.keiji.preview.standard",
                    nonce = "preview-nonce-from-client",
                    requestHash = "preview-request-hash-standard",
                    timestampMillis = System.currentTimeMillis()
                ),
                appIntegrity = dev.keiji.deviceintegrity.api.playintegrity.AppIntegrity(
                    appRecognitionVerdict = "MEETS_DEVICE_INTEGRITY",
                    packageName = "dev.keiji.preview.standard",
                    certificateSha256Digest = listOf("cert_std_1", "cert_std_2"),
                    versionCode = 456
                ),
                deviceIntegrity = dev.keiji.deviceintegrity.api.playintegrity.DeviceIntegrity(
                    deviceRecognitionVerdict = listOf(
                        "MEETS_DEVICE_INTEGRITY",
                        "MEETS_STRONG_INTEGRITY"
                    ),
                    deviceAttributes = dev.keiji.deviceintegrity.api.playintegrity.DeviceAttributes(
                        sdkVersion = 31
                    ),
                    recentDeviceActivity = dev.keiji.deviceintegrity.api.playintegrity.RecentDeviceActivity(
                        deviceActivityLevel = "LEVEL_2"
                    )
                ),
                accountDetails = dev.keiji.deviceintegrity.api.playintegrity.AccountDetails(
                    appLicensingVerdict = "LICENSED"
                ),
                environmentDetails = dev.keiji.deviceintegrity.api.playintegrity.EnvironmentDetails(
                    appAccessRiskVerdict = dev.keiji.deviceintegrity.api.playintegrity.AppAccessRiskVerdict(
                        appsDetected = listOf("std_app1", "std_app2")
                    ),
                    playProtectVerdict = "NO_ISSUES"
                )
            ),
            // Preview with dummy DeviceInfo and SecurityInfo
            deviceInfo = dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo(
                brand = "PreviewBrandStd",
                model = "PreviewModelStd",
                device = "PreviewDeviceStd",
                product = "PreviewProductStd",
                manufacturer = "PreviewManufacturerStd",
                hardware = "PreviewHardwareStd",
                board = "PreviewBoardStd",
                bootloader = "PreviewBootloaderStd",
                versionRelease = "13",
                sdkInt = 33,
                fingerprint = "PreviewFingerprintStd",
                securityPatch = "2023-08-05"
            ),
            securityInfo = dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo(
                isDeviceLockEnabled = false, isBiometricsEnabled = true,
                hasClass3Authenticator = false, hasStrongbox = true
            ),
        ),
        onContentBindingChange = {},
        onRequestToken = {},
        onRequestVerify = {}
    )
}
