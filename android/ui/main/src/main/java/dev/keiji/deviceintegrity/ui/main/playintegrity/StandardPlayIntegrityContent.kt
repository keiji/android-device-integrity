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
import androidx.compose.material3.OutlinedTextField
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
private fun StandardPlayIntegrityContentPreview() {
    StandardPlayIntegrityContent(
        uiState = StandardPlayIntegrityUiState(
            contentBinding = "preview-content-binding",
            integrityToken = "preview-token",
            progressValue = 0.0F,
            status = "Preview status text for Standard.",
            serverVerificationPayload = ServerVerificationPayload(
                playIntegrityResponse = PlayIntegrityResponseWrapper(
                    tokenPayloadExternal = TokenPayloadExternal(
                        requestDetails = RequestDetails(
                            requestPackageName = "dev.keiji.preview.standard",
                            nonce = "preview-nonce-from-client", // Standard API doesn't use server-nonce in requestDetails
                            requestHash = "preview-request-hash-standard",
                            timestampMillis = System.currentTimeMillis()
                        ),
                        appIntegrity = AppIntegrity(
                            appRecognitionVerdict = "MEETS_DEVICE_INTEGRITY",
                            packageName = "dev.keiji.preview.standard",
                            certificateSha256Digest = listOf("cert_std_1", "cert_std_2"),
                            versionCode = 456
                        ),
                        deviceIntegrity = DeviceIntegrity(
                            deviceRecognitionVerdict = listOf(
                                "MEETS_DEVICE_INTEGRITY",
                                "MEETS_STRONG_INTEGRITY"
                            ),
                            deviceAttributes = DeviceAttributes(
                                sdkVersion = 31
                            ),
                            recentDeviceActivity = RecentDeviceActivity(
                                deviceActivityLevel = "LEVEL_2"
                            )
                        ),
                        accountDetails = AccountDetails(
                            appLicensingVerdict = "LICENSED"
                        ),
                        environmentDetails = EnvironmentDetails(
                            appAccessRiskVerdict = AppAccessRiskVerdict(
                                appsDetected = listOf("std_app1", "std_app2")
                            ),
                            playProtectVerdict = "NO_ISSUES"
                        )
                    )
                ),
                deviceInfo = DeviceInfo(
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
                securityInfo = SecurityInfo(
                    isDeviceLockEnabled = false, isBiometricsEnabled = true,
                    hasClass3Authenticator = false, hasStrongbox = true
                ),
                googlePlayDeveloperServiceInfo = GooglePlayDeveloperServiceInfo(
                    googlePlayServicesVersion = "87654321",
                    isGooglePlayServicesAvailable = false
                )
            )
        ),
        onContentBindingChange = {},
        onRequestToken = {},
        onRequestVerify = {}
    )
}
