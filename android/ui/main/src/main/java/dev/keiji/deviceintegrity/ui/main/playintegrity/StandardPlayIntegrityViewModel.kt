package dev.keiji.deviceintegrity.ui.main.playintegrity

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.api.DeviceInfo
import dev.keiji.deviceintegrity.api.SecurityInfo
import dev.keiji.deviceintegrity.api.playintegrity.* // Ensure this wildcard import is here
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider
import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfoProvider
import dev.keiji.deviceintegrity.repository.contract.StandardPlayIntegrityTokenRepository
import dev.keiji.deviceintegrity.repository.contract.PlayIntegrityRepository
import dev.keiji.deviceintegrity.repository.contract.exception.ServerException
import dev.keiji.deviceintegrity.ui.main.common.DEBUG_VERIFY_TOKEN_DELAY_MS
import dev.keiji.deviceintegrity.ui.main.common.VERIFY_TOKEN_DELAY_MS
import dev.keiji.deviceintegrity.ui.main.InfoItem // Correctly at top
import dev.keiji.deviceintegrity.ui.main.util.DateFormatUtil // Correctly at top
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.security.MessageDigest
import android.util.Base64
import java.io.IOException
import java.util.UUID
import javax.inject.Inject

// PlayIntegrityProgressConstants will be imported from the new common file

@HiltViewModel
class StandardPlayIntegrityViewModel @Inject constructor(
    private val standardPlayIntegrityTokenRepository: StandardPlayIntegrityTokenRepository,
    private val playIntegrityRepository: PlayIntegrityRepository,
    private val deviceInfoProvider: DeviceInfoProvider,
    private val deviceSecurityStateProvider: DeviceSecurityStateProvider,
    private val googlePlayDeveloperServiceInfoProvider: GooglePlayDeveloperServiceInfoProvider,
    private val appInfoProvider: AppInfoProvider
) : ViewModel() {
    private val _uiState = MutableStateFlow(StandardPlayIntegrityUiState())
    val uiState: StateFlow<StandardPlayIntegrityUiState> = _uiState.asStateFlow()

    private var currentSessionId: String = ""

    init {
        viewModelScope.launch {
            val info = googlePlayDeveloperServiceInfoProvider.provide()
             _uiState.update { it.copy(googlePlayDeveloperServiceInfo = info) }
        }
    }

    fun updateContentBinding(newContent: String) {
        _uiState.update {
            it.copy(
                contentBinding = newContent,
                requestHashValue = ""
            )
        }
    }

    private fun transformPayloadToInfoItems(payload: ServerVerificationPayload?, currentSessionId: String, requestHashValue: String): List<InfoItem> {
        val items = mutableListOf<InfoItem>()
        if (payload == null) return items

        items.add(InfoItem("Session ID (Current)", currentSessionId, indentLevel = 0))
        if (requestHashValue.isNotEmpty()){
            items.add(InfoItem("Request Hash (Calculated by Client)", requestHashValue, indentLevel = 0))
        }

        payload.playIntegrityResponse.tokenPayloadExternal.let { token ->
            items.add(InfoItem("Play Integrity API Response", "", isHeader = true, indentLevel = 0))

            token.requestDetails?.let { rd ->
                items.add(InfoItem("Request Details", "", isHeader = true, indentLevel = 1))
                items.add(InfoItem("Request Package Name", rd.requestPackageName ?: "N/A", indentLevel = 2))
                rd.nonce?.let { items.add(InfoItem("Nonce", it, indentLevel = 2)) }
                items.add(InfoItem("Request Hash (from Server Response)", rd.requestHash ?: "N/A", indentLevel = 2))
                items.add(InfoItem("Timestamp", DateFormatUtil.formatEpochMilliToISO8601(rd.timestampMillis), indentLevel = 2))
            }

            token.appIntegrity?.let { ai ->
                items.add(InfoItem("App Integrity", "", isHeader = true, indentLevel = 1))
                items.add(InfoItem("App Recognition Verdict", ai.appRecognitionVerdict ?: "N/A", indentLevel = 2))
                items.add(InfoItem("Package Name", ai.packageName ?: "N/A", indentLevel = 2))
                items.add(InfoItem("Certificate SHA256", ai.certificateSha256Digest?.joinToString() ?: "N/A", indentLevel = 2))
                items.add(InfoItem("Version Code", ai.versionCode?.toString() ?: "N/A", indentLevel = 2))
            }

            token.deviceIntegrity?.let { di ->
                items.add(InfoItem("Device Integrity", "", isHeader = true, indentLevel = 1))
                items.add(InfoItem("Recognition Verdict", di.deviceRecognitionVerdict?.joinToString() ?: "N/A", indentLevel = 2))
                items.add(InfoItem("SDK Version", di.deviceAttributes?.sdkVersion?.toString() ?: "N/A", indentLevel = 2))
                items.add(InfoItem("Recent Device Activity", di.recentDeviceActivity?.deviceActivityLevel ?: "N/A", indentLevel = 2))
            }

            token.accountDetails?.let { ad ->
                items.add(InfoItem("Account Details", "", isHeader = true, indentLevel = 1))
                items.add(InfoItem("App Licensing Verdict", ad.appLicensingVerdict ?: "N/A", indentLevel = 2))
            }

            token.environmentDetails?.let { ed ->
                items.add(InfoItem("Environment Details", "", isHeader = true, indentLevel = 1))
                items.add(InfoItem("App Access Risk Verdict", ed.appAccessRiskVerdict?.appsDetected?.joinToString() ?: "N/A", indentLevel = 2))
                items.add(InfoItem("Play Protect Verdict", ed.playProtectVerdict ?: "N/A", indentLevel = 2))
            }
        }

        payload.deviceInfo.let { di ->
            items.add(InfoItem("Device Info (Reported by Client)", "", isHeader = true, indentLevel = 0))
            items.add(InfoItem("Brand", di.brand ?: "N/A", indentLevel = 1))
            items.add(InfoItem("Model", di.model ?: "N/A", indentLevel = 1))
            items.add(InfoItem("Device", di.device ?: "N/A", indentLevel = 1))
            items.add(InfoItem("Product", di.product ?: "N/A", indentLevel = 1))
            items.add(InfoItem("Manufacturer", di.manufacturer ?: "N/A", indentLevel = 1))
            items.add(InfoItem("Hardware", di.hardware ?: "N/A", indentLevel = 1))
            items.add(InfoItem("Board", di.board ?: "N/A", indentLevel = 1))
            items.add(InfoItem("Bootloader", di.bootloader ?: "N/A", indentLevel = 1))
            items.add(InfoItem("Version Release", di.versionRelease ?: "N/A", indentLevel = 1))
            items.add(InfoItem("SDK Int", di.sdkInt?.toString() ?: "N/A", indentLevel = 1))
            items.add(InfoItem("Fingerprint", di.fingerprint ?: "N/A", indentLevel = 1))
            items.add(InfoItem("Security Patch", di.securityPatch ?: "N/A", indentLevel = 1))
        }

        payload.securityInfo.let { si ->
            items.add(InfoItem("Security Info (Reported by Client)", "", isHeader = true, indentLevel = 0))
            items.add(InfoItem("Device Lock Enabled", si.isDeviceLockEnabled?.toString() ?: "N/A", indentLevel = 1))
            items.add(InfoItem("Biometrics Enabled", si.isBiometricsEnabled?.toString() ?: "N/A", indentLevel = 1))
            items.add(InfoItem("Has Class3 Authenticator", si.hasClass3Authenticator?.toString() ?: "N/A", indentLevel = 1))
            items.add(InfoItem("Has Strongbox", si.hasStrongbox?.toString() ?: "N/A", indentLevel = 1))
        }

        payload.googlePlayDeveloperServiceInfo?.let { gps ->
            items.add(InfoItem("Google Play Developer Service Info (Client)", "", isHeader = true, indentLevel = 0))
            items.add(InfoItem("Google Play Services Version Code", gps.versionCode.toString(), indentLevel = 1))
            items.add(InfoItem("Google Play Services Version Name", gps.versionName, indentLevel = 1))
        }
        return items
    }

    fun fetchIntegrityToken() {
        currentSessionId = UUID.randomUUID().toString()
        val currentContent = _uiState.value.contentBinding
        var encodedHash = ""
        val stringToHash = currentSessionId + currentContent
        if (stringToHash.isNotEmpty()) {
            try {
                val digest = MessageDigest.getInstance("SHA-256")
                val hashBytes = digest.digest(stringToHash.toByteArray(Charsets.UTF_8))
                encodedHash = Base64.encodeToString(hashBytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            } catch (e: Exception) {
                Log.e("StandardPlayIntegrityVM", "Error generating SHA-256 hash for '$stringToHash'", e)
            }
        }
        _uiState.update {
            it.copy(
                progressValue = PlayIntegrityProgressConstants.INDETERMINATE_PROGRESS,
                status = "Fetching token...",
                requestHashValue = "",
                errorMessages = emptyList(),
                resultInfoItems = emptyList(),
                serverVerificationPayload = null
            )
        }
        viewModelScope.launch {
            try {
                val hashToPass = if (currentContent.isNotEmpty()) encodedHash else null
                val token = standardPlayIntegrityTokenRepository.getToken(hashToPass)
                Log.d("StandardPlayIntegrityVM", "Integrity Token (Standard): $token")
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        integrityToken = token,
                        status = "Token fetched successfully (Standard API, see Logcat for token)",
                        errorMessages = emptyList(),
                        requestHashValue = if (currentContent.isNotEmpty()) encodedHash else "",
                        currentSessionId = currentSessionId
                    )
                }
            } catch (e: Exception) {
                Log.e("StandardPlayIntegrityVM", "Error fetching integrity token (Standard)", e)
                val specificErrorMessage = if (e is ServerException) {
                    "Server error: ${e.errorCode ?: "N/A"} - ${e.errorMessage ?: "Unknown"}"
                } else {
                    e.message ?: "Unknown error fetching integrity token (Standard)."
                }
                val userFacingStatus = "Error fetching integrity token (Standard): ${e.message ?: "Unknown error"}"
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        status = userFacingStatus,
                        errorMessages = listOf(specificErrorMessage),
                        requestHashValue = ""
                    )
                }
            }
        }
    }

    fun verifyToken() {
        val currentUiState = _uiState.value
        val token = currentUiState.integrityToken
        if (token.isBlank()) {
            _uiState.update {
                it.copy(status = "Token not available for verification.", errorMessages = listOf("Token is required for verification."))
            }
            return
        }
        if (currentSessionId.isBlank()) {
            _uiState.update {
                it.copy(status = "Session ID not available for verification.", errorMessages = listOf("Session ID is missing."))
            }
            return
        }
        _uiState.update {
            it.copy(
                progressValue = PlayIntegrityProgressConstants.INDETERMINATE_PROGRESS,
                status = "Preparing to verify token...",
                errorMessages = emptyList(),
                resultInfoItems = emptyList(),
                serverVerificationPayload = null
            )
        }
        val contentBindingForVerification = currentUiState.contentBinding
        viewModelScope.launch {
            try {
                val delayMs = if (appInfoProvider.isDebugBuild) DEBUG_VERIFY_TOKEN_DELAY_MS else VERIFY_TOKEN_DELAY_MS
                val totalSteps = (delayMs / PlayIntegrityProgressConstants.PROGRESS_UPDATE_INTERVAL_MS).toInt()
                var currentStep = 0
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.FULL_PROGRESS,
                        status = "Waiting for ${delayMs / 1000} seconds before verification..."
                    )
                }
                while (currentStep < totalSteps) {
                    delay(PlayIntegrityProgressConstants.PROGRESS_UPDATE_INTERVAL_MS)
                    currentStep++
                    val newProgress = PlayIntegrityProgressConstants.FULL_PROGRESS - (currentStep.toFloat() / totalSteps)
                    _uiState.update {
                        it.copy(progressValue = newProgress.coerceAtLeast(PlayIntegrityProgressConstants.NO_PROGRESS))
                    }
                }
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.INDETERMINATE_PROGRESS,
                        status = "Now verifying token with server..."
                    )
                }
                val deviceInfoData = DeviceInfo(
                    brand = deviceInfoProvider.BRAND, model = deviceInfoProvider.MODEL, device = deviceInfoProvider.DEVICE,
                    product = deviceInfoProvider.PRODUCT, manufacturer = deviceInfoProvider.MANUFACTURER, hardware = deviceInfoProvider.HARDWARE,
                    board = deviceInfoProvider.BOARD, bootloader = deviceInfoProvider.BOOTLOADER, versionRelease = deviceInfoProvider.VERSION_RELEASE,
                    sdkInt = deviceInfoProvider.SDK_INT, fingerprint = deviceInfoProvider.FINGERPRINT, securityPatch = deviceInfoProvider.SECURITY_PATCH
                )
                val securityInfo = SecurityInfo(
                    isDeviceLockEnabled = deviceSecurityStateProvider.isDeviceLockEnabled, isBiometricsEnabled = deviceSecurityStateProvider.isBiometricsEnabled,
                    hasClass3Authenticator = deviceSecurityStateProvider.hasClass3Authenticator, hasStrongbox = deviceSecurityStateProvider.hasStrongBox
                )
                val response = playIntegrityRepository.verifyTokenStandard(
                    integrityToken = token, sessionId = currentSessionId, contentBinding = contentBindingForVerification,
                    deviceInfo = deviceInfoData, securityInfo = securityInfo, googlePlayDeveloperServiceInfo = googlePlayDeveloperServiceInfoProvider.provide()
                )
                Log.d("StandardPlayIntegrityVM", "Verification Response: ${response.playIntegrityResponse.tokenPayloadExternal}")
                val resultItems = transformPayloadToInfoItems(response, currentSessionId, currentUiState.requestHashValue)
                val finalStatus = "Token verification complete."
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS, status = finalStatus,
                        serverVerificationPayload = response, resultInfoItems = resultItems,
                        errorMessages = emptyList(), currentSessionId = currentSessionId
                    )
                }
            } catch (e: ServerException) {
                Log.e("StandardPlayIntegrityVM", "Server error verifying token: ${e.errorCode} - ${e.errorMessage}", e)
                val specificErrorMessage = "Server error: ${e.errorCode ?: "N/A"} - ${e.errorMessage ?: "Unknown"}"
                val userFacingStatus = "Server error verifying token: ${e.errorMessage ?: "Unknown"}"
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS, status = userFacingStatus,
                        errorMessages = listOf(specificErrorMessage), serverVerificationPayload = null, resultInfoItems = emptyList()
                    )
                }
            } catch (e: IOException) {
                Log.e("StandardPlayIntegrityVM", "Network error verifying token", e)
                val specificErrorMessage = e.message ?: "Unknown network error."
                val userFacingStatus = "Network error verifying token: $specificErrorMessage"
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS, status = userFacingStatus,
                        errorMessages = listOf(specificErrorMessage), serverVerificationPayload = null, resultInfoItems = emptyList()
                    )
                }
            } catch (e: Exception) {
                Log.e("StandardPlayIntegrityVM", "Unknown error verifying token", e)
                val specificErrorMessage = e.message ?: "An unexpected error occurred."
                val userFacingStatus = "Unknown error verifying token: $specificErrorMessage"
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS, status = userFacingStatus,
                        errorMessages = listOf(specificErrorMessage), serverVerificationPayload = null, resultInfoItems = emptyList()
                    )
                }
            }
        }
    }
}
