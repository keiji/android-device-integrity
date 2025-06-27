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
        } else if (uiState.errorMessages.isNotEmpty()) {
            Text(text = "Error: ${uiState.errorMessages.joinToString("\n")}")
        } else if (uiState.verifyTokenResponse != null) {
            DisplayTokenResponse(uiState.verifyTokenResponse.tokenPayloadExternal)
        } else {
            Text(text = uiState.status) // Fallback status
        }
    }
}

@Composable
fun DisplayTokenResponse(tokenPayload: dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal?) {
    if (tokenPayload == null) {
        Text("Response: N/A")
        return
    }
    Column {
        Text("Request Details:")
        Text("  Package Name: ${tokenPayload.requestDetails?.requestPackageName ?: "N/A"}")
        Text("  Nonce: ${tokenPayload.requestDetails?.nonce ?: "N/A"}")
        Text("  Request Hash: ${tokenPayload.requestDetails?.requestHash ?: "N/A"}")
        Text("  Timestamp: ${tokenPayload.requestDetails?.timestampMillis ?: "N/A"}")

        Spacer(modifier = Modifier.height(8.dp))
        Text("App Integrity:")
        Text("  Recognition Verdict: ${tokenPayload.appIntegrity?.appRecognitionVerdict ?: "N/A"}")
        Text("  Package Name: ${tokenPayload.appIntegrity?.packageName ?: "N/A"}")
        Text("  Certificate SHA256: ${tokenPayload.appIntegrity?.certificateSha256Digest?.joinToString() ?: "N/A"}")
        Text("  Version Code: ${tokenPayload.appIntegrity?.versionCode ?: "N/A"}")

        Spacer(modifier = Modifier.height(8.dp))
        Text("Device Integrity:")
        Text("  Recognition Verdict: ${tokenPayload.deviceIntegrity?.deviceRecognitionVerdict?.joinToString() ?: "N/A"}")
        Text("  SDK Version: ${tokenPayload.deviceIntegrity?.deviceAttributes?.sdkVersion ?: "N/A"}")
        Text("  Device Activity Level: ${tokenPayload.deviceIntegrity?.recentDeviceActivity?.deviceActivityLevel ?: "N/A"}")


        Spacer(modifier = Modifier.height(8.dp))
        Text("Account Details:")
        Text("  Licensing Verdict: ${tokenPayload.accountDetails?.appLicensingVerdict ?: "N/A"}")

        Spacer(modifier = Modifier.height(8.dp))
        Text("Environment Details:")
        Text("  App Access Risk Verdict: ${tokenPayload.environmentDetails?.appAccessRiskVerdict?.appsDetected?.joinToString() ?: "N/A"}")
        Text("  Play Protect Verdict: ${tokenPayload.environmentDetails?.playProtectVerdict ?: "N/A"}")
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
