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
import dev.keiji.deviceintegrity.repository.contract.KeyAttestationRepository
import dev.keiji.deviceintegrity.repository.contract.exception.ServerException
import dev.keiji.deviceintegrity.ui.main.InfoItem
import dev.keiji.deviceintegrity.ui.main.common.KEY_ATTESTATION_DELAY_MS
import dev.keiji.deviceintegrity.ui.main.playintegrity.PlayIntegrityProgressConstants
import dev.keiji.deviceintegrity.ui.main.util.Base64Utils
import dev.keiji.deviceintegrity.ui.main.util.DateFormatUtil
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import java.security.SecureRandom
import java.util.UUID
import javax.inject.Inject
import kotlin.io.encoding.Base64

@HiltViewModel
class KeyAttestationViewModel @Inject constructor(
    private val keyPairRepository: KeyPairRepository,
    private val keyAttestationRepository: KeyAttestationRepository,
    private val deviceInfoProvider: DeviceInfoProvider,
    private val deviceSecurityStateProvider: DeviceSecurityStateProvider,
    @EC private val ecSigner: Signer,
    @RSA private val rsaSigner: Signer
) : ViewModel() {

    private val _uiState = MutableStateFlow(KeyAttestationUiState(isEcdhAvailable = deviceInfoProvider.isEcdhKeyAttestationAvailable))
    val uiState: StateFlow<KeyAttestationUiState> = _uiState.asStateFlow()

    private val _shareEventChannel = Channel<String>()
    val shareEventFlow = _shareEventChannel.receiveAsFlow()

    private val _copyEventChannel = Channel<String>()
    val copyEventFlow = _copyEventChannel.receiveAsFlow()

    fun onSelectedKeyTypeChange(newKeyType: CryptoAlgorithm) {
        viewModelScope.launch {
            // If the key type hasn't actually changed, do nothing.
            if (newKeyType == _uiState.value.selectedKeyType) {
                return@launch
            }

            // Clear existing key pair if it exists
            _uiState.value.generatedKeyPairData?.keyAlias?.let { alias ->
                try {
                    keyPairRepository.removeKeyPair(alias)
                } catch (e: Exception) {
                    Log.e("KeyAttestationViewModel", "Failed to delete key pair on key type change", e)
                }
            }

            // Update UI state: reset relevant fields
            _uiState.update {
                it.copy(
                    selectedKeyType = newKeyType,
                    saltOrNonce = "", // Clear salt/nonce
                    challenge = "",   // Clear challenge
                    serverPublicKey = "", // Clear server public key
                    generatedKeyPairData = null,
                    infoItems = emptyList(),
                    status = "Key algorithm changed to ${newKeyType.label}. Please fetch new Salt/Nonce and Challenge.",
                    progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                    sessionId = null // Also clear sessionId as it's tied to salt/nonce/challenge
                )
            }
        }
    }

    fun fetchNonceOrSaltChallenge() {
        viewModelScope.launch {
            // It's good practice to also clear any old keypair data if fetching new salt/nonce/challenge
            _uiState.value.generatedKeyPairData?.keyAlias?.let { alias ->
                try {
                    keyPairRepository.removeKeyPair(alias)
                } catch (e: Exception) {
                    Log.e("KeyAttestationViewModel", "Failed to delete key pair on fetching salt/nonce", e)
                }
            }

            val statusMessage = when (_uiState.value.selectedKeyType) {
                CryptoAlgorithm.ECDH -> "Preparing to fetch Salt/Challenge..."
                else -> "Preparing to fetch Nonce/Challenge..."
            }
            val fetchingMessage = when (_uiState.value.selectedKeyType) {
                CryptoAlgorithm.ECDH -> "Fetching Salt/Challenge..."
                else -> "Fetching Nonce/Challenge..."
            }
            val successMessage = when (_uiState.value.selectedKeyType) {
                CryptoAlgorithm.ECDH -> "Salt/Challenge fetched successfully."
                else -> "Nonce/Challenge fetched successfully."
            }
            val failureMessagePrefix = when (_uiState.value.selectedKeyType) {
                CryptoAlgorithm.ECDH -> "Failed to fetch Salt/Challenge"
                else -> "Failed to fetch Nonce/Challenge"
            }

            _uiState.update {
                it.copy(
                    status = statusMessage,
                    saltOrNonce = "", // Clear previous salt/nonce
                    challenge = "",   // Clear previous challenge
                    serverPublicKey = "", // Clear previous server public key
                    generatedKeyPairData = null, // Clear previous key data
                    infoItems = emptyList(),    // Clear previous results
                    progressValue = PlayIntegrityProgressConstants.FULL_PROGRESS
                )
            }

            val delayMs = KEY_ATTESTATION_DELAY_MS
            val totalSteps = (delayMs / PlayIntegrityProgressConstants.PROGRESS_UPDATE_INTERVAL_MS).toInt()
            var currentStep = 0

            while (currentStep < totalSteps) {
                delay(PlayIntegrityProgressConstants.PROGRESS_UPDATE_INTERVAL_MS)
                currentStep++
                val newProgress = PlayIntegrityProgressConstants.FULL_PROGRESS - (currentStep.toFloat() / totalSteps.toFloat())
                val waitingTimeSec = (delayMs - (currentStep * PlayIntegrityProgressConstants.PROGRESS_UPDATE_INTERVAL_MS)) / 1000.0
                _uiState.update { currentState ->
                    currentState.copy(
                        progressValue = newProgress.coerceAtLeast(PlayIntegrityProgressConstants.NO_PROGRESS),
                        status = "Waiting for ${String.format("%.1f", waitingTimeSec)}s..."
                    )
                }
            }

            _uiState.update {
                it.copy(
                    status = fetchingMessage,
                    progressValue = PlayIntegrityProgressConstants.INDETERMINATE_PROGRESS
                )
            }

            val newSessionId = UUID.randomUUID().toString()
            _uiState.update { it.copy(sessionId = newSessionId) }

            try {
                if (_uiState.value.selectedKeyType == CryptoAlgorithm.ECDH) {
                    val request = PrepareAgreementRequest(sessionId = newSessionId)
                    val response = keyAttestationRepository.prepareAgreement(request)
                    _uiState.update {
                        it.copy(
                            saltOrNonce = response.saltBase64UrlEncoded, // Store SALT for ECDH
                            challenge = response.challengeBase64UrlEncoded,
                            serverPublicKey = response.publicKeyBase64UrlEncoded, // Store server public key for ECDH
                            status = successMessage,
                            progressValue = PlayIntegrityProgressConstants.NO_PROGRESS
                        )
                    }
                } else {
                    val request = PrepareSignatureRequest(sessionId = newSessionId)
                    val response = keyAttestationRepository.prepareSignature(request)
                    _uiState.update {
                        it.copy(
                            saltOrNonce = response.nonceBase64UrlEncoded, // Store NONCE for EC/RSA
                            challenge = response.challengeBase64UrlEncoded,
                            status = successMessage,
                            progressValue = PlayIntegrityProgressConstants.NO_PROGRESS
                        )
                    }
                }
            } catch (e: ServerException) {
                Log.w("KeyAttestationViewModel", "ServerException fetching salt/nonce/challenge", e)
                val message = e.errorMessage ?: e.localizedMessage ?: "Unknown server error"
                _uiState.update {
                    it.copy(
                        status = "$failureMessagePrefix: Server Error ${e.errorCode ?: ""}: $message",
                        sessionId = null,
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS
                    )
                }
            } catch (e: IOException) {
                Log.w("KeyAttestationViewModel", "IOException fetching salt/nonce/challenge", e)
                _uiState.update {
                    it.copy(
                        status = "$failureMessagePrefix: Network Error: ${e.localizedMessage}",
                        sessionId = null,
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS
                    )
                }
            } catch (e: Exception) {
                Log.e("KeyAttestationViewModel", "Exception fetching salt/nonce/challenge", e)
                _uiState.update {
                    it.copy(
                        status = "$failureMessagePrefix: ${e.localizedMessage}",
                        sessionId = null,
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS
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
                    infoItems = emptyList(),
                    progressValue = PlayIntegrityProgressConstants.INDETERMINATE_PROGRESS
                )
            }

            val currentChallenge = uiState.value.challenge
            val currentSaltOrNonce = uiState.value.saltOrNonce

            if (currentSaltOrNonce.isEmpty() || currentChallenge.isEmpty()) {
                val missingItem = if (currentSaltOrNonce.isEmpty()) {
                    if (_uiState.value.selectedKeyType == CryptoAlgorithm.ECDH) "Salt" else "Nonce"
                } else {
                    "Challenge"
                }
                _uiState.update {
                    it.copy(
                        status = "$missingItem is not available. Fetch $missingItem/Challenge first.",
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS
                    )
                }
                return@launch
            }

            try {
                val decodedChallenge = withContext(Dispatchers.Default) {
                    Base64Utils.UrlSafeNoPadding.decode(currentChallenge)
                }

                val keyPairDataResult = withContext(Dispatchers.IO) {
                    when (uiState.value.selectedKeyType) {
                        CryptoAlgorithm.RSA -> keyPairRepository.generateRsaKeyPair(decodedChallenge)
                        CryptoAlgorithm.EC -> keyPairRepository.generateEcKeyPair(decodedChallenge)
                        CryptoAlgorithm.ECDH -> {
                            if (!deviceInfoProvider.isEcdhKeyAttestationAvailable) {
                                throw UnsupportedOperationException("このデバイスのAndroidのバージョンは構成証明付きのECDH鍵ペアに対応していません")
                            }
                            keyPairRepository.generateEcdhKeyPair(decodedChallenge)
                        }
                    }
                }

                _uiState.update {
                    it.copy(
                        generatedKeyPairData = keyPairDataResult,
                        status = "KeyPair generated successfully. Alias: ${keyPairDataResult.keyAlias}",
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS
                    )
                }
            } catch (e: Exception) {
                Log.e("KeyAttestationViewModel", "Failed to generate KeyPair", e)
                _uiState.update {
                    it.copy(
                        status = "Failed to generate KeyPair: ${e.message}",
                        generatedKeyPairData = null,
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS
                    )
                }
            }
        }
    }

    fun requestVerifyKeyAttestation() {
        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    status = "Preparing to verify KeyAttestation...",
                    infoItems = emptyList(),
                    progressValue = PlayIntegrityProgressConstants.FULL_PROGRESS
                )
            }

            val delayMs = KEY_ATTESTATION_DELAY_MS
            val totalSteps = (delayMs / PlayIntegrityProgressConstants.PROGRESS_UPDATE_INTERVAL_MS).toInt()
            var currentStep = 0

            while (currentStep < totalSteps) {
                delay(PlayIntegrityProgressConstants.PROGRESS_UPDATE_INTERVAL_MS)
                currentStep++
                val newProgress = PlayIntegrityProgressConstants.FULL_PROGRESS - (currentStep.toFloat() / totalSteps.toFloat())
                val waitingTimeSec = (delayMs - (currentStep * PlayIntegrityProgressConstants.PROGRESS_UPDATE_INTERVAL_MS)) / 1000.0
                _uiState.update { currentState ->
                    currentState.copy(
                        progressValue = newProgress.coerceAtLeast(PlayIntegrityProgressConstants.NO_PROGRESS),
                        status = "Waiting for ${String.format("%.1f", waitingTimeSec)}s..."
                    )
                }
            }

            _uiState.update {
                it.copy(
                    status = "Verifying KeyAttestation...",
                    progressValue = PlayIntegrityProgressConstants.INDETERMINATE_PROGRESS
                )
            }

            val currentSessionId = uiState.value.sessionId
            val currentKeyPairData = uiState.value.generatedKeyPairData
            val serverSaltOrNonceB64Url = uiState.value.saltOrNonce // Use saltOrNonce

            if (currentSessionId == null) {
                val itemToFetch = if (_uiState.value.selectedKeyType == CryptoAlgorithm.ECDH) "Salt/Challenge" else "Nonce/Challenge"
                _uiState.update {
                    it.copy(
                        status = "SessionId is missing. Fetch $itemToFetch first.",
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS
                    )
                }
                return@launch
            }
            val keyPair = currentKeyPairData?.keyPair
            if (keyPair == null) {
                _uiState.update {
                    it.copy(
                        status = "KeyPair is not generated yet.",
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS
                    )
                }
                return@launch
            }
            if (serverSaltOrNonceB64Url.isEmpty()) {
                val missingItem = if (_uiState.value.selectedKeyType == CryptoAlgorithm.ECDH) "Salt" else "Nonce"
                _uiState.update {
                    it.copy(
                        status = "Server $missingItem is missing. Fetch $missingItem/Challenge first.",
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS
                    )
                }
                return@launch
            }

            val clientNonce = ByteArray(32)
            SecureRandom().nextBytes(clientNonce)
            val decodedServerSaltOrNonce = Base64Utils.UrlSafeNoPadding.decode(serverSaltOrNonceB64Url) // Use decodedServerSaltOrNonce
            val dataToSign = decodedServerSaltOrNonce + clientNonce // Use decodedServerSaltOrNonce
            val privateKey = keyPair.private

            val selectedSigner = when (uiState.value.selectedKeyType) {
                CryptoAlgorithm.EC -> ecSigner
                CryptoAlgorithm.RSA -> rsaSigner
                CryptoAlgorithm.ECDH -> {
                    _uiState.update {
                        it.copy(
                            status = "ECDH is not supported for signing.",
                            progressValue = PlayIntegrityProgressConstants.NO_PROGRESS
                        )
                    }
                    return@launch
                }
            }
            val signatureData = selectedSigner.sign(dataToSign, privateKey)

            val signatureDataBase64UrlEncoded = Base64Utils.UrlSafeNoPadding.encode(signatureData)
            val clientNonceBase64UrlEncoded = Base64Utils.UrlSafeNoPadding.encode(clientNonce)
            val certificateChainBase64Encoded =
                currentKeyPairData.certificates.map { cert ->
                    Base64.Default.encode(cert.encoded)
                }
            val request = VerifySignatureRequest(
                sessionId = currentSessionId,
                signatureDataBase64UrlEncoded = signatureDataBase64UrlEncoded,
                clientNonceBase64UrlEncoded = clientNonceBase64UrlEncoded,
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

            try {
                val response = keyAttestationRepository.verifySignature(request)
                if (response.isVerified) {
                    val resultItems = buildVerificationResultList(response)
                    resultItems.addAll(convertDeviceInfoToAttestationItems(response.deviceInfo))
                    resultItems.addAll(convertSecurityInfoToAttestationItems(response.securityInfo))
                    _uiState.update {
                        it.copy(
                            status = "Verification successful.",
                            infoItems = resultItems,
                            progressValue = PlayIntegrityProgressConstants.NO_PROGRESS
                        )
                    }
                } else {
                    _uiState.update {
                        it.copy(
                            status = "Verification failed. Reason: ${response.reason ?: "Unknown"}",
                            progressValue = PlayIntegrityProgressConstants.NO_PROGRESS
                        )
                    }
                }
            } catch (e: ServerException) {
                Log.w("KeyAttestationViewModel", "ServerException verifying signature", e)
                val message = e.errorMessage ?: e.localizedMessage ?: "Unknown server error"
                _uiState.update {
                    it.copy(
                        status = "Failed to verify KeyAttestation: Server Error ${e.errorCode ?: ""}: $message",
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS
                    )
                }
            } catch (e: IOException) {
                Log.w("KeyAttestationViewModel", "IOException verifying signature", e)
                _uiState.update {
                    it.copy(
                        status = "Failed to verify KeyAttestation: Network Error: ${e.localizedMessage}",
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS
                    )
                }
            } catch (e: Exception) {
                Log.e("KeyAttestationViewModel", "Exception verifying signature", e)
                _uiState.update {
                    it.copy(
                        status = "Failed to verify KeyAttestation: ${e.localizedMessage}",
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS
                    )
                }
            }
        }
    }

    private fun convertDeviceInfoToAttestationItems(deviceInfo: DeviceInfo): List<InfoItem> {
        val items = mutableListOf<InfoItem>()
        items.add(InfoItem("Device Info", "", isHeader = true, indentLevel = 0))
        items.add(InfoItem("Brand", deviceInfo.brand, indentLevel = 1))
        items.add(InfoItem("Model", deviceInfo.model, indentLevel = 1))
        items.add(InfoItem("Device", deviceInfo.device, indentLevel = 1))
        items.add(InfoItem("Product", deviceInfo.product, indentLevel = 1))
        items.add(InfoItem("Manufacturer", deviceInfo.manufacturer, indentLevel = 1))
        items.add(InfoItem("Hardware", deviceInfo.hardware, indentLevel = 1))
        items.add(InfoItem("Board", deviceInfo.board, indentLevel = 1))
        items.add(InfoItem("Bootloader", deviceInfo.bootloader, indentLevel = 1))
        items.add(InfoItem("Version Release", deviceInfo.versionRelease, indentLevel = 1))
        items.add(InfoItem("SDK Int", deviceInfo.sdkInt.toString(), indentLevel = 1))
        items.add(InfoItem("Fingerprint", deviceInfo.fingerprint, indentLevel = 1))
        items.add(InfoItem("Security Patch", deviceInfo.securityPatch, indentLevel = 1))
        return items
    }

    private fun convertSecurityInfoToAttestationItems(securityInfo: SecurityInfo): List<InfoItem> {
        val items = mutableListOf<InfoItem>()
        items.add(InfoItem("Security Info", "", isHeader = true, indentLevel = 0))
        items.add(InfoItem("Is Device Lock Enabled", securityInfo.isDeviceLockEnabled.toString(), indentLevel = 1))
        items.add(InfoItem("Is Biometrics Enabled", securityInfo.isBiometricsEnabled.toString(), indentLevel = 1))
        items.add(InfoItem("Has Class3 Authenticator", securityInfo.hasClass3Authenticator.toString(), indentLevel = 1))
        items.add(InfoItem("Has Strongbox", securityInfo.hasStrongbox.toString(), indentLevel = 1))
        return items
    }

    private fun buildVerificationResultList(response: VerifySignatureResponse): MutableList<InfoItem> {
        val items = mutableListOf<InfoItem>()

        items.add(InfoItem("Session ID", response.sessionId))
        items.add(InfoItem("Is Verified", response.isVerified.toString()))
        response.reason?.let { items.add(InfoItem("Reason", it)) }

        val attestationInfo = response.attestationInfo
        items.add(InfoItem("Attestation Version", attestationInfo.attestationVersion.toString()))
        items.add(InfoItem("Attestation Security Level", attestationInfo.attestationSecurityLevel.toString()))
        items.add(InfoItem("KeyMint Version", attestationInfo.keymintVersion.toString()))
        items.add(InfoItem("KeyMint Security Level", attestationInfo.keymintSecurityLevel.toString()))
        items.add(InfoItem("Attestation Challenge", attestationInfo.attestationChallenge))

        addAuthorizationListItems(items, "Software Enforced Properties", attestationInfo.softwareEnforcedProperties)
        addAuthorizationListItems(items, "Hardware Enforced Properties", attestationInfo.hardwareEnforcedProperties)

        return items
    }

    private fun addAuthorizationListItems(
        items: MutableList<InfoItem>,
        header: String,
        props: AuthorizationList?
    ) {
        props ?: return
        items.add(InfoItem(header, "", isHeader = true))

        props.attestationApplicationId?.let { appId ->
            items.add(InfoItem("Attestation Application ID", "", indentLevel = 1, isHeader = true))
            appId.attestationApplicationId.let { items.add(InfoItem("Application ID", it, indentLevel = 2)) }
            appId.attestationApplicationVersionCode?.let { items.add(InfoItem("Version Code", it.toString(), indentLevel = 2)) }
            appId.applicationSignatures.forEachIndexed { index, signature ->
                items.add(InfoItem("Signature[${index}]", signature, indentLevel = 2))
            }
        }
        props.creationDatetime?.let { items.add(InfoItem("Creation Datetime", DateFormatUtil.formatEpochMilliToISO8601(it), indentLevel = 1)) }
        props.algorithm?.let { items.add(InfoItem("Algorithm", it.toString(), indentLevel = 1)) }
        props.origin?.let { items.add(InfoItem("Origin", it.toString(), indentLevel = 1)) }
        props.ecCurve?.let { items.add(InfoItem("EC Curve", it.toString(), indentLevel = 1)) }
        props.keySize?.let { items.add(InfoItem("Key Size", it.toString(), indentLevel = 1)) }
        props.purpose?.let { items.add(InfoItem("Purposes", it.joinToString(), indentLevel = 1)) }
        props.digest?.let { items.add(InfoItem("Digest", it.joinToString(), indentLevel = 1)) }
        props.padding?.let { items.add(InfoItem("Padding", it.joinToString(), indentLevel = 1)) }
        props.rsaPublicExponent?.let { items.add(InfoItem("RSA Public Exponent", it.toString(), indentLevel = 1)) }
        props.mgfDigest?.let { items.add(InfoItem("MGF Digest", it.joinToString(), indentLevel = 1)) }
        props.rollbackResistance?.let { items.add(InfoItem("Rollback Resistance", it.toString(), indentLevel = 1)) }
        props.earlyBootOnly?.let { items.add(InfoItem("Early Boot Only", it.toString(), indentLevel = 1)) }
        props.activeDateTime?.let { items.add(InfoItem("Active Datetime", DateFormatUtil.formatEpochMilliToISO8601(it), indentLevel = 1)) }
        props.originationExpireDateTime?.let { items.add(InfoItem("Origination Expire Datetime", DateFormatUtil.formatEpochMilliToISO8601(it), indentLevel = 1)) }
        props.usageExpireDateTime?.let { items.add(InfoItem("Usage Expire Datetime", DateFormatUtil.formatEpochMilliToISO8601(it), indentLevel = 1)) }
        props.usageCountLimit?.let { items.add(InfoItem("Usage Count Limit", it.toString(), indentLevel = 1)) }
        props.noAuthRequired?.let { items.add(InfoItem("No Auth Required", it.toString(), indentLevel = 1)) }
        props.userAuthType?.let { items.add(InfoItem("User Auth Type", it.toString(), indentLevel = 1)) }
        props.authTimeout?.let { items.add(InfoItem("Auth Timeout", it.toString(), indentLevel = 1)) }
        props.allowWhileOnBody?.let { items.add(InfoItem("Allow While On Body", it.toString(), indentLevel = 1)) }
        props.trustedUserPresenceRequired?.let { items.add(InfoItem("Trusted User Presence Required", it.toString(), indentLevel = 1)) }
        props.trustedConfirmationRequired?.let { items.add(InfoItem("Trusted Confirmation Required", it.toString(), indentLevel = 1)) }
        props.unlockedDeviceRequired?.let { items.add(InfoItem("Unlocked Device Required", it.toString(), indentLevel = 1)) }

        props.rootOfTrust?.let { rot ->
            items.add(InfoItem("Root of Trust", "", indentLevel = 1, isHeader = true))
            rot.deviceLocked?.let { items.add(InfoItem("Device Locked", it.toString(), indentLevel = 2)) }
            rot.verifiedBootState?.let { items.add(InfoItem("Verified Boot State", it.toString(), indentLevel = 2)) }
            rot.verifiedBootHash?.let { items.add(InfoItem("Verified Boot Hash", it, indentLevel = 2)) }
            rot.verifiedBootKey?.let { items.add(InfoItem("Verified Boot Key", it, indentLevel = 2)) }
        }

        props.osVersion?.let { items.add(InfoItem("OS Version", it.toString(), indentLevel = 1)) }
        props.osPatchLevel?.let { items.add(InfoItem("OS Patch Level", it.toString(), indentLevel = 1)) }
        props.attestationIdBrand?.let { items.add(InfoItem("Attestation ID Brand", it, indentLevel = 1)) }
        props.attestationIdDevice?.let { items.add(InfoItem("Attestation ID Device", it, indentLevel = 1)) }
        props.attestationIdProduct?.let { items.add(InfoItem("Attestation ID Product", it, indentLevel = 1)) }
        props.attestationIdSerial?.let { items.add(InfoItem("Attestation ID Serial", it, indentLevel = 1)) }
        props.attestationIdImei?.let { items.add(InfoItem("Attestation ID IMEI", it, indentLevel = 1)) }
        props.attestationIdMeid?.let { items.add(InfoItem("Attestation ID MEID", it, indentLevel = 1)) }
        props.attestationIdManufacturer?.let { items.add(InfoItem("Attestation ID Manufacturer", it, indentLevel = 1)) }
        props.attestationIdModel?.let { items.add(InfoItem("Attestation ID Model", it, indentLevel = 1)) }
        props.vendorPatchLevel?.let { items.add(InfoItem("Vendor Patch Level", it.toString(), indentLevel = 1)) }
        props.bootPatchLevel?.let { items.add(InfoItem("Boot Patch Level", it.toString(), indentLevel = 1)) }
        props.deviceUniqueAttestation?.let { items.add(InfoItem("Device Unique Attestation", it.toString(), indentLevel = 1)) }
        props.attestationIdSecondImei?.let { items.add(InfoItem("Attestation ID Second IMEI", it, indentLevel = 1)) }
        props.moduleHash?.let { items.add(InfoItem("Module Hash", it, indentLevel = 1)) }
    }

    fun onCopyResultsClicked() {
        val items = uiState.value.infoItems
        if (items.isNotEmpty()) {
            val textToCopy = InfoItemFormatter.formatInfoItems(items)
            viewModelScope.launch {
                _copyEventChannel.send(textToCopy)
            }
        }
    }

    fun onShareResultsClicked() {
        val items = uiState.value.infoItems
        if (items.isNotEmpty()) {
            val textToShare = InfoItemFormatter.formatInfoItems(items)
            viewModelScope.launch {
                _shareEventChannel.send(textToShare)
            }
        }
    }
}
