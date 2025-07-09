package dev.keiji.deviceintegrity.ui.main.keyattestation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.api.DeviceInfo
import dev.keiji.deviceintegrity.api.SecurityInfo
import dev.keiji.deviceintegrity.api.keyattestation.*
import dev.keiji.deviceintegrity.crypto.contract.Signer
import dev.keiji.deviceintegrity.crypto.contract.qualifier.EC
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider
import dev.keiji.deviceintegrity.repository.contract.KeyPairRepository
import dev.keiji.deviceintegrity.ui.main.util.Base64Utils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID
import javax.inject.Inject
import kotlin.io.encoding.Base64

@HiltViewModel
class KeyAttestationViewModel @Inject constructor(
    private val keyPairRepository: KeyPairRepository,
    private val keyAttestationVerifyApiClient: KeyAttestationVerifyApiClient,
    private val deviceInfoProvider: DeviceInfoProvider,
    private val deviceSecurityStateProvider: DeviceSecurityStateProvider,
    @EC private val signer: Signer
) : ViewModel() {

    private val _uiState = MutableStateFlow(KeyAttestationUiState())
    val uiState: StateFlow<KeyAttestationUiState> = _uiState.asStateFlow()

    private val _shareEventChannel = Channel<String>()
    val shareEventFlow = _shareEventChannel.receiveAsFlow()

    private val _copyEventChannel = Channel<String>()
    val copyEventFlow = _copyEventChannel.receiveAsFlow()

    fun onSelectedKeyTypeChange(newKeyType: CryptoAlgorithm) {
        _uiState.update { it.copy(selectedKeyType = newKeyType) }
    }

    fun fetchNonceChallenge() {
        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    status = "Fetching Nonce/Challenge...",
                    nonce = "",
                    challenge = "",
                    verificationResultItems = emptyList() // Clear previous results
                )
            }
            try {
                val newSessionId = UUID.randomUUID().toString()
                _uiState.update { it.copy(sessionId = newSessionId) }

                val request = PrepareRequest(sessionId = newSessionId)
                val response = withContext(Dispatchers.IO) {
                    keyAttestationVerifyApiClient.prepare(request)
                }

                _uiState.update {
                    it.copy(
                        nonce = response.nonceBase64UrlEncoded,
                        challenge = response.challengeBase64UrlEncoded,
                        status = "Nonce/Challenge fetched successfully."
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        status = "Failed to fetch Nonce/Challenge: ${e.message}",
                        sessionId = null
                    )
                }
            }
        }
    }

    fun generateKeyPair() {
        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    status = "Generating KeyPair...",
                    generatedKeyPairData = null,
                    verificationResultItems = emptyList() // Clear previous results
                )
            }

            val currentChallenge = uiState.value.challenge
            if (currentChallenge.isEmpty()) {
                _uiState.update { it.copy(status = "Challenge is not available. Fetch Nonce/Challenge first.") }
                return@launch
            }

            try {
                val decodedChallenge = withContext(Dispatchers.Default) {
                    Base64Utils.UrlSafeNoPadding.decode(currentChallenge)
                }
                var keyPairDataResult: KeyPairData? = null // Initialize to null
                try {
                    val decodedChallenge = withContext(Dispatchers.Default) { // Moved decode into try block
                        Base64Utils.UrlSafeNoPadding.decode(currentChallenge)
                    }

                    keyPairDataResult = withContext(Dispatchers.IO) {
                        when (uiState.value.selectedKeyType) {
                            CryptoAlgorithm.RSA -> keyPairRepository.generateRsaKeyPair(decodedChallenge)
                            CryptoAlgorithm.EC -> keyPairRepository.generateEcKeyPair(decodedChallenge)
                            CryptoAlgorithm.ECDH -> throw UnsupportedOperationException("ECDH key generation is not yet implemented.")
                        }
                    }

                    // If successful, update UI
                    _uiState.update {
                        it.copy(
                            generatedKeyPairData = keyPairDataResult, // This will be non-null if no exception
                            status = "KeyPair generated successfully. Alias: ${keyPairDataResult!!.keyAlias}" // keyPairDataResult is asserted non-null here as success implies it.
                        )
                    }

                } catch (e: Exception) { // Single catch block for all exceptions in the try
                    Log.e("KeyAttestationViewModel", "Failed to generate KeyPair or decode challenge", e)
                    _uiState.update { it.copy(status = "Failed to generate KeyPair: ${e.message}", generatedKeyPairData = null) }
                }
            }
        }
    }

    fun requestVerifyKeyAttestation() {
        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    status = "Verifying KeyAttestation...",
                    verificationResultItems = emptyList() // Clear previous results
                )
            }

            val currentSessionId = uiState.value.sessionId
            val currentKeyPairData = uiState.value.generatedKeyPairData
            val serverNonceB64Url = uiState.value.nonce

            if (currentSessionId == null) {
                _uiState.update { it.copy(status = "SessionId is missing. Fetch Nonce/Challenge first.") }
                return@launch
            }
            val keyPair = currentKeyPairData?.keyPair
            if (keyPair == null) {
                _uiState.update { it.copy(status = "KeyPair is not generated yet.") }
                return@launch
            }
            if (serverNonceB64Url.isEmpty()) {
                _uiState.update { it.copy(status = "Server Nonce is missing. Fetch Nonce/Challenge first.") }
                return@launch
            }

            try {
                val response = withContext(Dispatchers.IO) {
                    val nonceB = ByteArray(32)
                    SecureRandom().nextBytes(nonceB)
                    val decodedServerNonce = Base64Utils.UrlSafeNoPadding.decode(serverNonceB64Url)
                    val dataToSign = decodedServerNonce + nonceB
                    val privateKey = keyPair.private
                    val signatureData = signer.sign(dataToSign, privateKey)
                    val signatureDataBase64UrlEncoded = Base64Utils.UrlSafeNoPadding.encode(signatureData)
                    val nonceBBase64UrlEncoded = Base64Utils.UrlSafeNoPadding.encode(nonceB)
                    val certificateChainBase64Encoded =
                        currentKeyPairData.certificates.map { cert ->
                            Base64.Default.encode(cert.encoded)
                        }
                    val request = VerifySignatureRequest(
                        sessionId = currentSessionId,
                        signatureDataBase64UrlEncoded = signatureDataBase64UrlEncoded,
                        nonceBBase64UrlEncoded = nonceBBase64UrlEncoded,
                        certificateChainBase64Encoded = certificateChainBase64Encoded,
                        deviceInfo = DeviceInfo(
                            brand = deviceInfoProvider.BRAND,
                            model = deviceInfoProvider.MODEL,
                            device = deviceInfoProvider.DEVICE,
                            product = deviceInfoProvider.PRODUCT,
                            manufacturer = deviceInfoProvider.MANUFACTURER,
                            hardware = deviceInfoProvider.HARDWARE,
                            board = deviceInfoProvider.BOARD,
                            bootloader = deviceInfoProvider.BOOTLOADER,
                            versionRelease = deviceInfoProvider.VERSION_RELEASE,
                            sdkInt = deviceInfoProvider.SDK_INT,
                            fingerprint = deviceInfoProvider.FINGERPRINT,
                            securityPatch = deviceInfoProvider.SECURITY_PATCH
                        ),
                        securityInfo = SecurityInfo(
                            isDeviceLockEnabled = deviceSecurityStateProvider.isDeviceLockEnabled,
                            isBiometricsEnabled = deviceSecurityStateProvider.isBiometricsEnabled,
                            hasClass3Authenticator = deviceSecurityStateProvider.hasClass3Authenticator,
                            hasStrongbox = deviceSecurityStateProvider.hasStrongBox
                        )
                    )
                    keyAttestationVerifyApiClient.verifySignature(request)
                }

                if (response.isVerified) {
                    val resultItems = buildVerificationResultList(response)
                    // Append Device Info and Security Info to the main list
                    resultItems.addAll(convertDeviceInfoToAttestationItems(response.deviceInfo))
                    resultItems.addAll(convertSecurityInfoToAttestationItems(response.securityInfo))

                    _uiState.update {
                        it.copy(
                            status = "Verification successful.", // General status
                            verificationResultItems = resultItems
                        )
                    }
                } else {
                    _uiState.update {
                        it.copy(status = "Verification failed. Reason: ${response.reason ?: "Unknown"}")
                    }
                }

            } catch (e: Exception) {
                _uiState.update { it.copy(status = "Failed to verify KeyAttestation: ${e.message}") }
            }
        }
    }

    private fun convertDeviceInfoToAttestationItems(deviceInfo: DeviceInfo): List<AttestationInfoItem> {
        val items = mutableListOf<AttestationInfoItem>()
        items.add(AttestationInfoItem("Device Info", "", isHeader = true, indentLevel = 0))
        items.add(AttestationInfoItem("Brand", deviceInfo.brand, indentLevel = 1))
        items.add(AttestationInfoItem("Model", deviceInfo.model, indentLevel = 1))
        items.add(AttestationInfoItem("Device", deviceInfo.device, indentLevel = 1))
        items.add(AttestationInfoItem("Product", deviceInfo.product, indentLevel = 1))
        items.add(AttestationInfoItem("Manufacturer", deviceInfo.manufacturer, indentLevel = 1))
        items.add(AttestationInfoItem("Hardware", deviceInfo.hardware, indentLevel = 1))
        items.add(AttestationInfoItem("Board", deviceInfo.board, indentLevel = 1))
        items.add(AttestationInfoItem("Bootloader", deviceInfo.bootloader, indentLevel = 1))
        items.add(AttestationInfoItem("Version Release", deviceInfo.versionRelease, indentLevel = 1))
        items.add(AttestationInfoItem("SDK Int", deviceInfo.sdkInt.toString(), indentLevel = 1))
        items.add(AttestationInfoItem("Fingerprint", deviceInfo.fingerprint, indentLevel = 1))
        items.add(AttestationInfoItem("Security Patch", deviceInfo.securityPatch, indentLevel = 1))
        return items
    }

    private fun convertSecurityInfoToAttestationItems(securityInfo: SecurityInfo): List<AttestationInfoItem> {
        val items = mutableListOf<AttestationInfoItem>()
        items.add(AttestationInfoItem("Security Info", "", isHeader = true, indentLevel = 0))
        items.add(AttestationInfoItem("Is Device Lock Enabled", securityInfo.isDeviceLockEnabled.toString(), indentLevel = 1))
        items.add(AttestationInfoItem("Is Biometrics Enabled", securityInfo.isBiometricsEnabled.toString(), indentLevel = 1))
        items.add(AttestationInfoItem("Has Class3 Authenticator", securityInfo.hasClass3Authenticator.toString(), indentLevel = 1))
        items.add(AttestationInfoItem("Has Strongbox", securityInfo.hasStrongbox.toString(), indentLevel = 1))
        return items
    }

    private fun buildVerificationResultList(response: VerifySignatureResponse): MutableList<AttestationInfoItem> {
        val items = mutableListOf<AttestationInfoItem>()

        items.add(AttestationInfoItem("Session ID", response.sessionId))
        items.add(AttestationInfoItem("Is Verified", response.isVerified.toString()))
        response.reason?.let { items.add(AttestationInfoItem("Reason", it)) }

        // Access properties from the new attestationInfo object
        val attestationInfo = response.attestationInfo
        items.add(AttestationInfoItem("Attestation Version", attestationInfo.attestationVersion.toString()))
        items.add(AttestationInfoItem("Attestation Security Level", attestationInfo.attestationSecurityLevel.toString()))
        items.add(AttestationInfoItem("KeyMint Version", attestationInfo.keymintVersion.toString()))
        items.add(AttestationInfoItem("KeyMint Security Level", attestationInfo.keymintSecurityLevel.toString()))
        items.add(AttestationInfoItem("Attestation Challenge", attestationInfo.attestationChallenge))

        addAuthorizationListItems(items, "Software Enforced Properties", attestationInfo.softwareEnforcedProperties)
        addAuthorizationListItems(items, "Hardware Enforced Properties", attestationInfo.hardwareEnforcedProperties)

        return items
    }

    private fun addAuthorizationListItems(
        items: MutableList<AttestationInfoItem>,
        header: String,
        props: AuthorizationList?
    ) {
        props ?: return
        items.add(AttestationInfoItem(header, "", isHeader = true))

        props.attestationApplicationId?.let { appId ->
            items.add(AttestationInfoItem("Attestation Application ID", "", indentLevel = 1, isHeader = true))
            appId.attestationApplicationId.let { items.add(AttestationInfoItem("Application ID", it, indentLevel = 2)) }
            appId.attestationApplicationVersionCode?.let { items.add(AttestationInfoItem("Version Code", it.toString(), indentLevel = 2)) }
            appId.applicationSignatures.forEachIndexed { index, signature ->
                items.add(AttestationInfoItem("Signature[${index}]", signature, indentLevel = 2))
            }
        }
        props.creationDatetime?.let { items.add(AttestationInfoItem("Creation Datetime", formatEpochMilliToISO8601(it), indentLevel = 1)) }
        props.algorithm?.let { items.add(AttestationInfoItem("Algorithm", it.toString(), indentLevel = 1)) }
        props.origin?.let { items.add(AttestationInfoItem("Origin", it, indentLevel = 1)) }
        props.ecCurve?.let { items.add(AttestationInfoItem("EC Curve", it.toString(), indentLevel = 1)) }
        props.keySize?.let { items.add(AttestationInfoItem("Key Size", it.toString(), indentLevel = 1)) }
        props.purpose?.let { items.add(AttestationInfoItem("Purposes", it.joinToString(), indentLevel = 1)) }
        props.digests?.let { items.add(AttestationInfoItem("Digests", it.joinToString(), indentLevel = 1)) }
        props.noAuthRequired?.let { items.add(AttestationInfoItem("No Auth Required", it.toString(), indentLevel = 1)) }

        props.rootOfTrust?.let { rot ->
            items.add(AttestationInfoItem("Root of Trust", "", indentLevel = 1, isHeader = true))
            rot.deviceLocked?.let { items.add(AttestationInfoItem("Device Locked", it.toString(), indentLevel = 2)) }
            rot.verifiedBootState?.let { items.add(AttestationInfoItem("Verified Boot State", it.toString(), indentLevel = 2)) }
            rot.verifiedBootHash?.let { items.add(AttestationInfoItem("Verified Boot Hash", it, indentLevel = 2)) }
            rot.verifiedBootKey?.let { items.add(AttestationInfoItem("Verified Boot Key", it, indentLevel = 2)) }
        }

        props.osPatchLevel?.let { items.add(AttestationInfoItem("OS Patch Level", it.toString(), indentLevel = 1)) }
        props.vendorPatchLevel?.let { items.add(AttestationInfoItem("Vendor Patch Level", it.toString(), indentLevel = 1)) }
        props.bootPatchLevel?.let { items.add(AttestationInfoItem("Boot Patch Level", it.toString(), indentLevel = 1)) }
    }

    private fun formatEpochMilliToISO8601(epochMilli: Long): String {
        val date = Date(epochMilli)
        // Replaced XXX with ZZZZZ for API level 23 compatibility.
        // ZZZZZ produces a format like "GMT-07:00" or "UTC" if UTC.
        // For UTC, it will be "UTC", to get "Z", one might need to replace "UTC" with "Z" manually.
        // However, the requirement is ISO/IEC 8601, and "yyyy-MM-dd'T'HH:mm:ss.SSSZZZZZ" is compliant.
        val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZZZZZ", Locale.US)
        format.timeZone = TimeZone.getTimeZone("UTC")
        var formattedDate = format.format(date)
        // Replace "UTC" with "Z" for the common ISO 8601 UTC designator
        if (formattedDate.endsWith("UTC")) {
            formattedDate = formattedDate.substring(0, formattedDate.length - 3) + "Z"
        }
        return formattedDate
    }

    fun onCopyResultsClicked() {
        val items = uiState.value.verificationResultItems
        if (items.isNotEmpty()) {
            val textToCopy = AttestationResultFormatter.formatAttestationResults(items)
            viewModelScope.launch {
                _copyEventChannel.send(textToCopy)
            }
        }
    }

    fun onShareResultsClicked() {
        val items = uiState.value.verificationResultItems
        if (items.isNotEmpty()) {
            val textToShare = AttestationResultFormatter.formatAttestationResults(items)
            viewModelScope.launch {
                _shareEventChannel.send(textToShare)
            }
        }
    }
}
