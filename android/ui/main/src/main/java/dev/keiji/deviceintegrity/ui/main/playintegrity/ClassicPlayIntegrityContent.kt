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
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dev.keiji.deviceintegrity.api.playintegrity.AccountDetails
import dev.keiji.deviceintegrity.api.playintegrity.AppAccessRiskVerdict
import dev.keiji.deviceintegrity.api.playintegrity.AppIntegrity
import dev.keiji.deviceintegrity.api.playintegrity.DeviceAttributes
import dev.keiji.deviceintegrity.api.playintegrity.DeviceIntegrity
import dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo
import dev.keiji.deviceintegrity.api.playintegrity.EnvironmentDetails
import dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityResponseWrapper
import dev.keiji.deviceintegrity.api.playintegrity.RecentDeviceActivity
import dev.keiji.deviceintegrity.api.playintegrity.RequestDetails
import dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo
import dev.keiji.deviceintegrity.api.playintegrity.ServerVerificationPayload
import dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal
import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfo
import dev.keiji.deviceintegrity.ui.theme.ButtonHeight

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
        Spacer(modifier = Modifier.height(8.dp))
        Button(
            onClick = { onFetchNonce() },
            enabled = uiState.isFetchNonceButtonEnabled,
            modifier = Modifier
                .fillMaxWidth()
                .height(ButtonHeight)
        ) {
            Text(text = "Fetch Nonce")
        }
        if (uiState.nonce.isNotEmpty()) {
            Text(text = "Nonce: ${uiState.nonce}")
        }

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
        HorizontalDivider() // Add a divider
        Spacer(modifier = Modifier.height(16.dp))

        StatusDisplayArea(
            progressValue = uiState.progressValue,
            errorMessages = uiState.errorMessages,
            statusText = uiState.status,
            serverVerificationPayload = uiState.serverVerificationPayload,
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
            progressValue = 0.0F,
            status = "Preview status text for Classic.",
            serverVerificationPayload = ServerVerificationPayload(
                playIntegrityResponse = PlayIntegrityResponseWrapper(
                    tokenPayloadExternal = TokenPayloadExternal(
                        requestDetails = RequestDetails(
                            requestPackageName = "dev.keiji.preview",
                            nonce = "preview-nonce-from-server",
                            requestHash = "preview-request-hash",
                            timestampMillis = System.currentTimeMillis()
                        ),
                        appIntegrity = AppIntegrity(
                            appRecognitionVerdict = "MEETS_DEVICE_INTEGRITY",
                            packageName = "dev.keiji.preview",
                            certificateSha256Digest = listOf("cert1", "cert2"),
                            versionCode = 123
                        ),
                        deviceIntegrity = DeviceIntegrity(
                            deviceRecognitionVerdict = listOf("MEETS_DEVICE_INTEGRITY"),
                            deviceAttributes = DeviceAttributes(
                                sdkVersion = 30
                            ),
                            recentDeviceActivity = RecentDeviceActivity(
                                deviceActivityLevel = "LEVEL_1"
                            )
                        ),
                        accountDetails = AccountDetails(
                            appLicensingVerdict = "LICENSED"
                        ),
                        environmentDetails = EnvironmentDetails(
                            appAccessRiskVerdict = AppAccessRiskVerdict(
                                appsDetected = listOf("app1", "app2")
                            ),
                            playProtectVerdict = "NO_ISSUES"
                        )
                    )
                ),
                deviceInfo = DeviceInfo(
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
                securityInfo = SecurityInfo(
                    isDeviceLockEnabled = true, isBiometricsEnabled = false,
                    hasClass3Authenticator = true, hasStrongbox = false
                ),
                googlePlayDeveloperServiceInfo = GooglePlayDeveloperServiceInfo(
                    versionCode = 100,
                    versionName = ""
                )
            )
        ),
        onFetchNonce = {},
        onRequestToken = {},
        onRequestVerify = {}
    )
}
