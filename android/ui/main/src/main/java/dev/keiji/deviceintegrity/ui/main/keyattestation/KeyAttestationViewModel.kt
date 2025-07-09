package dev.keiji.deviceintegrity.ui.main.keyattestation

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.api.DeviceInfo
import dev.keiji.deviceintegrity.api.SecurityInfo
import dev.keiji.deviceintegrity.api.keyattestation.*
import dev.keiji.deviceintegrity.crypto.contract.Signer
import dev.keiji.deviceintegrity.crypto.contract.qualifier.EC
import dev.keiji.deviceintegrity.crypto.contract.qualifier.RSA
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider
import dev.keiji.deviceintegrity.repository.contract.KeyPairRepository
import dev.keiji.deviceintegrity.ui.main.util.Base64Utils
import dev.keiji.deviceintegrity.ui.main.util.DateFormatUtil
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
    @EC private val ecSigner: Signer,
    @RSA private val rsaSigner: Signer
) : ViewModel() {

    private val _uiState = MutableStateFlow(KeyAttestationUiState())
    val uiState: StateFlow<KeyAttestationUiState> = _uiState.asStateFlow()

    private val _shareEventChannel = Channel<String>()
    val shareEventFlow = _shareEventChannel.receiveAsFlow()

    private val _copyEventChannel = Channel<String>()
    val copyEventFlow = _copyEventChannel.receiveAsFlow()

    fun onSelectedKeyTypeChange(newKeyType: CryptoAlgorithm) {
        // Delete existing key pair and reset UI
        uiState.value.generatedKeyPairData?.keyAlias?.let { alias ->
            viewModelScope.launch {
                try {
                    keyPairRepository.removeKeyPair(alias)
                } catch (e: Exception) {
                    Log.e("KeyAttestationViewModel", "Failed to delete key pair", e)
                    // Optionally update UI with error, though the main goal is to reset
                }
            }
        }
        _uiState.update {
            it.copy(
                selectedKeyType = newKeyType,
                generatedKeyPairData = null, // Reset key pair data
                verificationResultItems = emptyList(), // Clear verification results
                status = "Key algorithm changed. Please generate a new key pair." // Inform user
            )
        }
    }

    fun fetchNonceChallenge() {
        viewModelScope.launch {
            // Delete existing key pair and reset UI before fetching nonce
            uiState.value.generatedKeyPairData?.keyAlias?.let { alias ->
                try {
                    keyPairRepository.removeKeyPair(alias)
                } catch (e: Exception) {
                    Log.e("KeyAttestationViewModel", "Failed to delete key pair on fetching nonce", e)
                }
            }
            _uiState.update {
                it.copy(
                    status = "Fetching Nonce/Challenge...",
                    nonce = "",
                    challenge = "",
                    generatedKeyPairData = null, // Reset key pair data
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
                    verificationResultItems = emptyList()
                )
            }

            val currentChallenge = uiState.value.challenge
            if (currentChallenge.isEmpty()) {
                _uiState.update { it.copy(status = "Challenge is not available. Fetch Nonce/Challenge first.") }
                return@launch
            }

            try { // Single try block for the entire operation
                val decodedChallenge = withContext(Dispatchers.Default) {
                    Base64Utils.UrlSafeNoPadding.decode(currentChallenge)
                }

                val keyPairDataResult = withContext(Dispatchers.IO) {
                    when (uiState.value.selectedKeyType) {
                        CryptoAlgorithm.RSA -> keyPairRepository.generateRsaKeyPair(decodedChallenge)
                        CryptoAlgorithm.EC -> keyPairRepository.generateEcKeyPair(decodedChallenge)
                        CryptoAlgorithm.ECDH -> throw UnsupportedOperationException("ECDH key generation is not yet implemented.")
                    }
                }

                // keyPairDataResult is asserted non-null here as success (no exception) implies it.
                _uiState.update {
                    it.copy(
                        generatedKeyPairData = keyPairDataResult,
                        status = "KeyPair generated successfully. Alias: ${keyPairDataResult.keyAlias}"
                    )
                }
            } catch (e: Exception) { // Single catch block for all exceptions
                Log.e("KeyAttestationViewModel", "Failed to generate KeyPair", e)
                _uiState.update { it.copy(status = "Failed to generate KeyPair: ${e.message}", generatedKeyPairData = null) }
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

                    val selectedSigner = when (uiState.value.selectedKeyType) {
                        CryptoAlgorithm.EC -> ecSigner
                        CryptoAlgorithm.RSA -> rsaSigner
                        CryptoAlgorithm.ECDH -> throw IllegalStateException("ECDH is not supported for signing.")
                    }
                    val signatureData = selectedSigner.sign(dataToSign, privateKey)

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
        props.creationDatetime?.let { items.add(AttestationInfoItem("Creation Datetime", DateFormatUtil.formatEpochMilliToISO8601(it), indentLevel = 1)) }
        props.algorithm?.let { items.add(AttestationInfoItem("Algorithm", it.toString(), indentLevel = 1)) }
        props.origin?.let { items.add(AttestationInfoItem("Origin", it.toString(), indentLevel = 1)) }
        props.ecCurve?.let { items.add(AttestationInfoItem("EC Curve", it.toString(), indentLevel = 1)) }
        props.keySize?.let { items.add(AttestationInfoItem("Key Size", it.toString(), indentLevel = 1)) }
        props.purpose?.let { items.add(AttestationInfoItem("Purposes", it.joinToString(), indentLevel = 1)) }
        props.digest?.let { items.add(AttestationInfoItem("Digest", it.joinToString(), indentLevel = 1)) }
        props.padding?.let { items.add(AttestationInfoItem("Padding", it.joinToString(), indentLevel = 1)) }
        props.rsaPublicExponent?.let { items.add(AttestationInfoItem("RSA Public Exponent", it.toString(), indentLevel = 1)) }
        props.mgfDigest?.let { items.add(AttestationInfoItem("MGF Digest", it.joinToString(), indentLevel = 1)) }
        props.rollbackResistance?.let { items.add(AttestationInfoItem("Rollback Resistance", it.toString(), indentLevel = 1)) }
        props.earlyBootOnly?.let { items.add(AttestationInfoItem("Early Boot Only", it.toString(), indentLevel = 1)) }
        props.activeDateTime?.let { items.add(AttestationInfoItem("Active Datetime", DateFormatUtil.formatEpochMilliToISO8601(it), indentLevel = 1)) }
        props.originationExpireDateTime?.let { items.add(AttestationInfoItem("Origination Expire Datetime", DateFormatUtil.formatEpochMilliToISO8601(it), indentLevel = 1)) }
        props.usageExpireDateTime?.let { items.add(AttestationInfoItem("Usage Expire Datetime", DateFormatUtil.formatEpochMilliToISO8601(it), indentLevel = 1)) }
        props.usageCountLimit?.let { items.add(AttestationInfoItem("Usage Count Limit", it.toString(), indentLevel = 1)) }
        props.noAuthRequired?.let { items.add(AttestationInfoItem("No Auth Required", it.toString(), indentLevel = 1)) }
        props.userAuthType?.let { items.add(AttestationInfoItem("User Auth Type", it.toString(), indentLevel = 1)) }
        props.authTimeout?.let { items.add(AttestationInfoItem("Auth Timeout", it.toString(), indentLevel = 1)) }
        props.allowWhileOnBody?.let { items.add(AttestationInfoItem("Allow While On Body", it.toString(), indentLevel = 1)) }
        props.trustedUserPresenceRequired?.let { items.add(AttestationInfoItem("Trusted User Presence Required", it.toString(), indentLevel = 1)) }
        props.trustedConfirmationRequired?.let { items.add(AttestationInfoItem("Trusted Confirmation Required", it.toString(), indentLevel = 1)) }
        props.unlockedDeviceRequired?.let { items.add(AttestationInfoItem("Unlocked Device Required", it.toString(), indentLevel = 1)) }

        props.rootOfTrust?.let { rot ->
            items.add(AttestationInfoItem("Root of Trust", "", indentLevel = 1, isHeader = true))
            rot.deviceLocked?.let { items.add(AttestationInfoItem("Device Locked", it.toString(), indentLevel = 2)) }
            rot.verifiedBootState?.let { items.add(AttestationInfoItem("Verified Boot State", it.toString(), indentLevel = 2)) }
            rot.verifiedBootHash?.let { items.add(AttestationInfoItem("Verified Boot Hash", it, indentLevel = 2)) }
            rot.verifiedBootKey?.let { items.add(AttestationInfoItem("Verified Boot Key", it, indentLevel = 2)) }
        }

        props.osVersion?.let { items.add(AttestationInfoItem("OS Version", it.toString(), indentLevel = 1)) }
        props.osPatchLevel?.let { items.add(AttestationInfoItem("OS Patch Level", it.toString(), indentLevel = 1)) }
        props.attestationIdBrand?.let { items.add(AttestationInfoItem("Attestation ID Brand", it, indentLevel = 1)) }
        props.attestationIdDevice?.let { items.add(AttestationInfoItem("Attestation ID Device", it, indentLevel = 1)) }
        props.attestationIdProduct?.let { items.add(AttestationInfoItem("Attestation ID Product", it, indentLevel = 1)) }
        props.attestationIdSerial?.let { items.add(AttestationInfoItem("Attestation ID Serial", it, indentLevel = 1)) }
        props.attestationIdImei?.let { items.add(AttestationInfoItem("Attestation ID IMEI", it, indentLevel = 1)) }
        props.attestationIdMeid?.let { items.add(AttestationInfoItem("Attestation ID MEID", it, indentLevel = 1)) }
        props.attestationIdManufacturer?.let { items.add(AttestationInfoItem("Attestation ID Manufacturer", it, indentLevel = 1)) }
        props.attestationIdModel?.let { items.add(AttestationInfoItem("Attestation ID Model", it, indentLevel = 1)) }
        props.vendorPatchLevel?.let { items.add(AttestationInfoItem("Vendor Patch Level", it.toString(), indentLevel = 1)) }
        props.bootPatchLevel?.let { items.add(AttestationInfoItem("Boot Patch Level", it.toString(), indentLevel = 1)) }
        props.deviceUniqueAttestation?.let { items.add(AttestationInfoItem("Device Unique Attestation", it.toString(), indentLevel = 1)) }
        props.attestationIdSecondImei?.let { items.add(AttestationInfoItem("Attestation ID Second IMEI", it, indentLevel = 1)) }
        props.moduleHash?.let { items.add(AttestationInfoItem("Module Hash", it, indentLevel = 1)) }
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
