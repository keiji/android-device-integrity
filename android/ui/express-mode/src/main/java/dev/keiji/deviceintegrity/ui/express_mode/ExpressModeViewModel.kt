package dev.keiji.deviceintegrity.ui.express_mode

import android.content.Context
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import dev.keiji.deviceintegrity.api.DeviceInfo
import dev.keiji.deviceintegrity.api.SecurityInfo
import dev.keiji.deviceintegrity.api.keyattestation.AuthorizationList
import dev.keiji.deviceintegrity.api.keyattestation.CertificateDetails
import dev.keiji.deviceintegrity.api.keyattestation.VerifySignatureRequest
import dev.keiji.deviceintegrity.api.keyattestation.VerifySignatureResponse
import dev.keiji.deviceintegrity.api.playintegrity.ServerVerificationPayload
import dev.keiji.deviceintegrity.crypto.contract.Signer
import dev.keiji.deviceintegrity.crypto.contract.qualifier.EC
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider
import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfoProvider
import dev.keiji.deviceintegrity.repository.contract.KeyAttestationRepository
import dev.keiji.deviceintegrity.repository.contract.KeyPairData
import dev.keiji.deviceintegrity.repository.contract.KeyPairRepository
import dev.keiji.deviceintegrity.repository.contract.PlayIntegrityRepository
import dev.keiji.deviceintegrity.repository.contract.StandardPlayIntegrityTokenRepository
import dev.keiji.deviceintegrity.ui.common.InfoItem
import dev.keiji.deviceintegrity.ui.util.Base64Utils
import dev.keiji.deviceintegrity.ui.util.DateFormatUtil
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import javax.inject.Inject
import kotlin.io.encoding.Base64

@HiltViewModel
class ExpressModeViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val standardPlayIntegrityTokenRepository: StandardPlayIntegrityTokenRepository,
    private val playIntegrityRepository: PlayIntegrityRepository,
    private val keyPairRepository: KeyPairRepository,
    private val keyAttestationRepository: KeyAttestationRepository,
    private val deviceInfoProvider: DeviceInfoProvider,
    private val deviceSecurityStateProvider: DeviceSecurityStateProvider,
    private val googlePlayDeveloperServiceInfoProvider: GooglePlayDeveloperServiceInfoProvider,
    private val appInfoProvider: AppInfoProvider,
    @EC private val ecSigner: Signer
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        ExpressModeUiState(
            progress = 0,
            maxProgress = 10,
            resultInfoItems = emptyList(),
            statusResId = null,
        )
    )
    val uiState: StateFlow<ExpressModeUiState> = _uiState.asStateFlow()

    private val _uiEvent = MutableStateFlow<ExpressModeUiEvent?>(null)
    val uiEvent: StateFlow<ExpressModeUiEvent?> = _uiEvent.asStateFlow()

    init {
        startVerification()
    }

    private fun startVerification() {
        viewModelScope.launch {
            // 1. Wait 10 seconds (count down every 50ms)
            val waitSeconds = 10
            val interval = 50L
            val totalSteps = (waitSeconds * 1000 / interval).toInt()

            _uiState.update {
                it.copy(
                    maxProgress = totalSteps,
                    progress = totalSteps,
                    statusResId = R.string.status_preparing
                )
            }
            for (i in totalSteps downTo 1) {
                _uiState.update {
                    it.copy(
                        progress = i,
                        statusResId = R.string.status_preparing
                    )
                }
                delay(interval)
            }
            _uiState.update { it.copy(progress = 0, statusResId = R.string.status_preparing) }

            // 2. Play Integrity Check
            _uiState.update {
                it.copy(
                    statusResId = R.string.status_play_integrity,
                    progress = -1
                )
            }
            val (isPlayIntegritySuccess, playIntegrityItems) = runPlayIntegrityCheck()

            // 3. Key Attestation Check
            _uiState.update {
                it.copy(
                    statusResId = R.string.status_key_attestation,
                    progress = -1
                )
            }
            val (isKeyAttestationSuccess, keyAttestationItems) = runKeyAttestationCheck()

            // 4. Show Results
            _uiState.update {
                it.copy(
                    progress = 0,
                    isProgressVisible = false,
                    statusResId = R.string.status_complete,
                    playIntegrityInfoItems = playIntegrityItems,
                    keyAttestationInfoItems = keyAttestationItems,
                    isPlayIntegritySuccess = isPlayIntegritySuccess,
                    isKeyAttestationSuccess = isKeyAttestationSuccess
                )
            }
        }
    }

    private suspend fun runPlayIntegrityCheck(): Pair<Boolean, List<InfoItem>> {
        val currentSessionId = UUID.randomUUID().toString()
        val currentContent = UUID.randomUUID().toString() // Random content
        var encodedHash = ""
        val stringToHash = currentSessionId + currentContent
        if (stringToHash.isNotEmpty()) {
            try {
                val digest = MessageDigest.getInstance("SHA-256")
                val hashBytes = digest.digest(stringToHash.toByteArray(Charsets.UTF_8))
                encodedHash = Base64Utils.UrlSafeNoPadding.encode(hashBytes)
            } catch (e: Exception) {
                Log.e(
                    "ExpressModeViewModel",
                    "Error generating SHA-256 hash for '$stringToHash'",
                    e
                )
            }
        }

        try {
            val hashToPass = if (currentContent.isNotEmpty()) encodedHash else null
            val token = standardPlayIntegrityTokenRepository.getToken(hashToPass)

            val deviceInfoData = DeviceInfo(
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
            )
            val securityInfo = SecurityInfo(
                isDeviceLockEnabled = deviceSecurityStateProvider.isDeviceLockEnabled,
                isBiometricsEnabled = deviceSecurityStateProvider.isBiometricsEnabled,
                hasClass3Authenticator = deviceSecurityStateProvider.hasClass3Authenticator,
                hasStrongbox = deviceSecurityStateProvider.hasStrongBox
            )
            val response = playIntegrityRepository.verifyTokenStandard(
                integrityToken = token,
                sessionId = currentSessionId,
                contentBinding = currentContent,
                deviceInfo = deviceInfoData,
                securityInfo = securityInfo,
                googlePlayDeveloperServiceInfo = googlePlayDeveloperServiceInfoProvider.provide()
            )

            return true to transformPayloadToInfoItems(response, currentSessionId, encodedHash)

        } catch (e: Exception) {
            Log.e("ExpressModeViewModel", "Error in Play Integrity Check", e)
            return false to listOf(
                InfoItem(context.getString(R.string.result_label_result), "Failed: " + (e.message ?: "Unknown Error"), isHeader = true)
            )
        }
    }

    private suspend fun runKeyAttestationCheck(): Pair<Boolean, List<InfoItem>> {
        try {
            // 1. Fetch Nonce/Challenge
            val prepareResponse = keyAttestationRepository.prepareSignature()
            val serverNonceB64Url = prepareResponse.nonceBase64UrlEncoded
            val challengeB64Url = prepareResponse.challengeBase64UrlEncoded
            val sessionId = prepareResponse.sessionId

            val decodedChallenge = Base64Utils.UrlSafeNoPadding.decode(challengeB64Url)

            // 2. Generate Key Pair
            val preferStrongBox = deviceSecurityStateProvider.hasStrongBox

            var keyPairData: KeyPairData? = null
            try {
                keyPairData = keyPairRepository.generateEcKeyPair(
                    decodedChallenge,
                    preferStrongBox = preferStrongBox,
                    includeIdAttestation = true
                )
            } catch (e: Exception) {
                // Retry without ID Attestation
                _uiState.update {
                    it.copy(statusResId = R.string.status_retry_without_id_attestation)
                }
                delay(2000) // Show message for a bit

                 keyPairData = keyPairRepository.generateEcKeyPair(
                    decodedChallenge,
                    preferStrongBox = preferStrongBox,
                    includeIdAttestation = false
                )
            }

            val currentKeyPairData = keyPairData ?: throw IllegalStateException("Failed to generate key pair")

            // 3. Verify
             val clientNonce = ByteArray(32)
             SecureRandom().nextBytes(clientNonce)
             val decodedServerNonce = Base64Utils.UrlSafeNoPadding.decode(serverNonceB64Url)
             val dataToSign = decodedServerNonce + clientNonce
             val privateKey = currentKeyPairData.keyPair?.private
                 ?: throw IllegalStateException("Private key not available")

             val signatureData = ecSigner.sign(dataToSign, privateKey)

             val signatureDataBase64UrlEncoded = Base64Utils.UrlSafeNoPadding.encode(signatureData)
             val clientNonceBase64UrlEncoded = Base64Utils.UrlSafeNoPadding.encode(clientNonce)
             val certificateChainBase64Encoded =
                 currentKeyPairData.certificates.map { cert ->
                     Base64.Default.encode(cert.encoded)
                 }

             val request = VerifySignatureRequest(
                 sessionId = sessionId,
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

             val response = keyAttestationRepository.verifySignature(request)

             val resultItems = buildVerificationResultList(response)
             resultItems.addAll(convertDeviceInfoToAttestationItems(response.deviceInfo))
             resultItems.addAll(convertSecurityInfoToAttestationItems(response.securityInfo))

             return response.isVerified to resultItems

        } catch (e: Exception) {
            Log.e("ExpressModeViewModel", "Error in Key Attestation Check", e)
             return false to listOf(
                InfoItem(context.getString(R.string.result_label_result), "Failed: " + (e.message ?: "Unknown Error"), isHeader = true)
            )
        }
    }

    private fun transformPayloadToInfoItems(
        payload: ServerVerificationPayload?,
        currentSessionId: String,
        requestHashValue: String
    ): List<InfoItem> {
        val items = mutableListOf<InfoItem>()
        if (payload == null) return items

        items.add(InfoItem(context.getString(R.string.header_session_id) + " (Current)", currentSessionId, indentLevel = 0))
        if (requestHashValue.isNotEmpty()) {
            items.add(
                InfoItem(
                    context.getString(R.string.header_request_hash) + " (Calculated by Client)",
                    requestHashValue,
                    indentLevel = 0
                )
            )
        }

        payload.playIntegrityResponse.tokenPayloadExternal.let { token ->
            items.add(
                InfoItem(
                    context.getString(R.string.header_play_integrity_api_response),
                    "",
                    isHeader = true,
                    indentLevel = 0
                )
            )

            token.requestDetails?.let { rd ->
                items.add(InfoItem(context.getString(R.string.header_request_details), "", isHeader = true, indentLevel = 1))
                items.add(
                    InfoItem(
                        context.getString(R.string.item_label_request_package_name),
                        rd.requestPackageName ?: "N/A",
                        indentLevel = 2
                    )
                )
                rd.nonce?.let { items.add(InfoItem(context.getString(R.string.item_label_nonce), it, indentLevel = 2)) }
                items.add(
                    InfoItem(
                        context.getString(R.string.item_label_request_hash_server),
                        rd.requestHash ?: "N/A",
                        indentLevel = 2
                    )
                )
                items.add(
                    InfoItem(
                        context.getString(R.string.item_label_timestamp),
                        DateFormatUtil.formatEpochMilliToISO8601(rd.timestampMillis),
                        indentLevel = 2
                    )
                )
            }

            token.appIntegrity?.let { ai ->
                items.add(InfoItem(context.getString(R.string.header_app_integrity), "", isHeader = true, indentLevel = 1))
                items.add(
                    InfoItem(
                        context.getString(R.string.item_label_app_recognition_verdict),
                        ai.appRecognitionVerdict ?: "N/A",
                        indentLevel = 2
                    )
                )
                items.add(
                    InfoItem(
                        context.getString(R.string.item_label_package_name),
                        ai.packageName ?: "N/A",
                        indentLevel = 2
                    )
                )
                items.add(
                    InfoItem(
                        context.getString(R.string.item_label_certificate_sha256),
                        ai.certificateSha256Digest?.joinToString() ?: "N/A",
                        indentLevel = 2
                    )
                )
                items.add(
                    InfoItem(
                        context.getString(R.string.item_label_version_code),
                        ai.versionCode?.toString() ?: "N/A",
                        indentLevel = 2
                    )
                )
            }

            token.deviceIntegrity?.let { di ->
                items.add(InfoItem(context.getString(R.string.header_device_integrity), "", isHeader = true, indentLevel = 1))
                items.add(
                    InfoItem(
                        context.getString(R.string.item_label_recognition_verdict),
                        di.deviceRecognitionVerdict?.joinToString() ?: "N/A",
                        indentLevel = 2
                    )
                )
                items.add(
                    InfoItem(
                        context.getString(R.string.item_label_sdk_version),
                        di.deviceAttributes?.sdkVersion?.toString() ?: "N/A",
                        indentLevel = 2
                    )
                )
                items.add(
                    InfoItem(
                        context.getString(R.string.item_label_recent_device_activity),
                        di.recentDeviceActivity?.deviceActivityLevel ?: "N/A",
                        indentLevel = 2
                    )
                )
            }

            token.accountDetails?.let { ad ->
                items.add(InfoItem(context.getString(R.string.header_account_details), "", isHeader = true, indentLevel = 1))
                items.add(
                    InfoItem(
                        context.getString(R.string.item_label_app_licensing_verdict),
                        ad.appLicensingVerdict ?: "N/A",
                        indentLevel = 2
                    )
                )
            }

            token.environmentDetails?.let { ed ->
                items.add(InfoItem(context.getString(R.string.header_environment_details), "", isHeader = true, indentLevel = 1))
                items.add(
                    InfoItem(
                        context.getString(R.string.item_label_app_access_risk_verdict),
                        ed.appAccessRiskVerdict?.appsDetected?.joinToString() ?: "N/A",
                        indentLevel = 2
                    )
                )
                items.add(
                    InfoItem(
                        context.getString(R.string.item_label_play_protect_verdict),
                        ed.playProtectVerdict ?: "N/A",
                        indentLevel = 2
                    )
                )
            }
        }

        payload.deviceInfo.let { di ->
            items.add(
                InfoItem(
                    context.getString(R.string.header_device_info),
                    "",
                    isHeader = true,
                    indentLevel = 0
                )
            )
            items.add(InfoItem(context.getString(R.string.item_label_brand), di.brand ?: "N/A", indentLevel = 1))
            items.add(InfoItem(context.getString(R.string.item_label_model), di.model ?: "N/A", indentLevel = 1))
            items.add(InfoItem(context.getString(R.string.item_label_device), di.device ?: "N/A", indentLevel = 1))
            items.add(InfoItem(context.getString(R.string.item_label_product), di.product ?: "N/A", indentLevel = 1))
            items.add(InfoItem(context.getString(R.string.item_label_manufacturer), di.manufacturer ?: "N/A", indentLevel = 1))
            items.add(InfoItem(context.getString(R.string.item_label_hardware), di.hardware ?: "N/A", indentLevel = 1))
            items.add(InfoItem(context.getString(R.string.item_label_board), di.board ?: "N/A", indentLevel = 1))
            items.add(InfoItem(context.getString(R.string.item_label_bootloader), di.bootloader ?: "N/A", indentLevel = 1))
            items.add(InfoItem(context.getString(R.string.item_label_version_release), di.versionRelease ?: "N/A", indentLevel = 1))
            items.add(InfoItem(context.getString(R.string.item_label_sdk_int), di.sdkInt?.toString() ?: "N/A", indentLevel = 1))
            items.add(InfoItem(context.getString(R.string.item_label_fingerprint), di.fingerprint ?: "N/A", indentLevel = 1))
            items.add(InfoItem(context.getString(R.string.item_label_security_patch), di.securityPatch ?: "N/A", indentLevel = 1))
        }

        payload.securityInfo.let { si ->
            items.add(
                InfoItem(
                    context.getString(R.string.header_security_info),
                    "",
                    isHeader = true,
                    indentLevel = 0
                )
            )
            items.add(
                InfoItem(
                    context.getString(R.string.item_label_device_lock_enabled),
                    si.isDeviceLockEnabled?.toString() ?: "N/A",
                    indentLevel = 1
                )
            )
            items.add(
                InfoItem(
                    context.getString(R.string.item_label_biometrics_enabled),
                    si.isBiometricsEnabled?.toString() ?: "N/A",
                    indentLevel = 1
                )
            )
            items.add(
                InfoItem(
                    context.getString(R.string.item_label_class_3_authenticator),
                    si.hasClass3Authenticator?.toString() ?: "N/A",
                    indentLevel = 1
                )
            )
            items.add(
                InfoItem(
                    context.getString(R.string.item_label_strongbox),
                    si.hasStrongbox?.toString() ?: "N/A",
                    indentLevel = 1
                )
            )
        }

        payload.googlePlayDeveloperServiceInfo?.let { gps ->
            items.add(
                InfoItem(
                    context.getString(R.string.header_google_play_service_info),
                    "",
                    isHeader = true,
                    indentLevel = 0
                )
            )
            items.add(
                InfoItem(
                    context.getString(R.string.item_label_google_play_services_version_code),
                    gps.versionCode.toString(),
                    indentLevel = 1
                )
            )
            items.add(
                InfoItem(
                    context.getString(R.string.item_label_google_play_services_version_name),
                    gps.versionName,
                    indentLevel = 1
                )
            )
        }
        return items
    }

    private fun buildVerificationResultList(response: VerifySignatureResponse): MutableList<InfoItem> {
        val items = mutableListOf<InfoItem>()

        items.add(InfoItem(context.getString(R.string.header_session_id), response.sessionId))
        items.add(InfoItem(context.getString(R.string.result_label_verified), response.isVerified.toString()))
        response.reason?.let {
            items.add(InfoItem(context.getString(R.string.result_label_reason), it))
            items.add(InfoItem.DIVIDER)
        }

        response.attestationInfo?.let { attestationInfo ->
            items.add(InfoItem(context.getString(R.string.result_label_attestation_version), attestationInfo.attestationVersion.toString()))
            items.add(
                InfoItem(
                    context.getString(R.string.result_label_attestation_security_level),
                    LocalValueConverter.convertSecurityLevelToString(attestationInfo.attestationSecurityLevel)
                )
            )
            items.add(InfoItem(context.getString(R.string.result_label_keymint_version), attestationInfo.keymintVersion.toString()))
            items.add(
                InfoItem(
                    context.getString(R.string.result_label_keymint_security_level),
                    LocalValueConverter.convertSecurityLevelToString(attestationInfo.keymintSecurityLevel)
                )
            )
            items.add(InfoItem(context.getString(R.string.result_label_attestation_challenge), attestationInfo.attestationChallenge))

            addAuthorizationListItems(
                items,
                context.getString(R.string.header_software_enforced),
                attestationInfo.softwareEnforcedProperties
            )
            addAuthorizationListItems(
                items,
                context.getString(R.string.header_hardware_enforced),
                attestationInfo.hardwareEnforcedProperties
            )
        }

        if (response.certificateChain.isNotEmpty()) {
            addCertificateChainInfo(items, response.certificateChain)
        }

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
            items.add(
                InfoItem(
                    "Attestation Application ID",
                    "",
                    indentLevel = 1,
                    isHeader = true
                )
            )
            appId.attestationApplicationId.let {
                items.add(
                    InfoItem(
                        "Application ID",
                        it,
                        indentLevel = 2
                    )
                )
            }
            appId.attestationApplicationVersionCode?.let {
                items.add(
                    InfoItem(
                        "Version Code",
                        it.toString(),
                        indentLevel = 2
                    )
                )
            }
            appId.applicationSignatures.forEachIndexed { index, signature ->
                items.add(InfoItem("Signature[${index}]", signature, indentLevel = 2))
            }
        }
        props.creationDatetime?.let {
            items.add(
                InfoItem(
                    "Creation Datetime",
                    DateFormatUtil.formatEpochMilliToISO8601(it),
                    indentLevel = 1
                )
            )
        }
        props.algorithm?.let {
            items.add(
                InfoItem(
                    "Algorithm",
                    LocalValueConverter.convertAlgorithmToString(it),
                    indentLevel = 1
                )
            )
        }
        props.origin?.let {
            items.add(
                InfoItem(
                    "Origin",
                    LocalValueConverter.convertOriginToString(it),
                    indentLevel = 1
                )
            )
        }
        props.ecCurve?.let {
            items.add(
                InfoItem(
                    "EC Curve",
                    LocalValueConverter.convertEcCurveToString(it),
                    indentLevel = 1
                )
            )
        }
        props.keySize?.let { items.add(InfoItem("Key Size", it.toString(), indentLevel = 1)) }
        props.purpose?.let {
            val purposes = it.joinToString { purpose ->
                LocalValueConverter.convertPurposeToString(purpose)
            }
            items.add(InfoItem("Purposes", purposes, indentLevel = 1))
        }
        props.digest?.let {
            val digests = it.joinToString { digest ->
                LocalValueConverter.convertDigestToString(digest)
            }
            items.add(InfoItem("Digest", digests, indentLevel = 1))
        }
        props.padding?.let {
            val paddings = it.joinToString { padding ->
                LocalValueConverter.convertPaddingToString(padding)
            }
            items.add(InfoItem("Padding", paddings, indentLevel = 1))
        }
        props.rsaPublicExponent?.let {
            items.add(
                InfoItem(
                    "RSA Public Exponent",
                    it.toString(),
                    indentLevel = 1
                )
            )
        }
        props.mgfDigest?.let {
            val digests = it.joinToString { digest ->
                LocalValueConverter.convertDigestToString(digest)
            }
            items.add(InfoItem("MGF Digest", digests, indentLevel = 1))
        }
        props.rollbackResistance?.let {
            items.add(
                InfoItem(
                    "Rollback Resistance",
                    it.toString(),
                    indentLevel = 1
                )
            )
        }
        props.earlyBootOnly?.let {
            items.add(
                InfoItem(
                    "Early Boot Only",
                    it.toString(),
                    indentLevel = 1
                )
            )
        }
        props.activeDateTime?.let {
            items.add(
                InfoItem(
                    "Active Datetime",
                    DateFormatUtil.formatEpochMilliToISO8601(it),
                    indentLevel = 1
                )
            )
        }
        props.originationExpireDateTime?.let {
            items.add(
                InfoItem(
                    "Origination Expire Datetime",
                    DateFormatUtil.formatEpochMilliToISO8601(it),
                    indentLevel = 1
                )
            )
        }
        props.usageExpireDateTime?.let {
            items.add(
                InfoItem(
                    "Usage Expire Datetime",
                    DateFormatUtil.formatEpochMilliToISO8601(it),
                    indentLevel = 1
                )
            )
        }
        props.usageCountLimit?.let {
            items.add(
                InfoItem(
                    "Usage Count Limit",
                    it.toString(),
                    indentLevel = 1
                )
            )
        }
        props.noAuthRequired?.let {
            items.add(
                InfoItem(
                    "No Auth Required",
                    it.toString(),
                    indentLevel = 1
                )
            )
        }
        props.userAuthType?.let {
            items.add(
                InfoItem(
                    "User Auth Type",
                    it.toString(),
                    indentLevel = 1
                )
            )
        }
        props.authTimeout?.let {
            items.add(
                InfoItem(
                    "Auth Timeout",
                    it.toString(),
                    indentLevel = 1
                )
            )
        }
        props.allowWhileOnBody?.let {
            items.add(
                InfoItem(
                    "Allow While On Body",
                    it.toString(),
                    indentLevel = 1
                )
            )
        }
        props.trustedUserPresenceRequired?.let {
            items.add(
                InfoItem(
                    "Trusted User Presence Required",
                    it.toString(),
                    indentLevel = 1
                )
            )
        }
        props.trustedConfirmationRequired?.let {
            items.add(
                InfoItem(
                    "Trusted Confirmation Required",
                    it.toString(),
                    indentLevel = 1
                )
            )
        }
        props.unlockedDeviceRequired?.let {
            items.add(
                InfoItem(
                    "Unlocked Device Required",
                    it.toString(),
                    indentLevel = 1
                )
            )
        }

        props.rootOfTrust?.let { rot ->
            items.add(InfoItem(context.getString(R.string.header_root_of_trust), "", indentLevel = 1, isHeader = true))
            rot.deviceLocked?.let {
                items.add(
                    InfoItem(
                        "Device Locked",
                        it.toString(),
                        indentLevel = 2
                    )
                )
            }
            rot.verifiedBootState?.let {
                items.add(
                    InfoItem(
                        "Verified Boot State",
                        LocalValueConverter.convertVerifiedBootStateToString(it),
                        indentLevel = 2
                    )
                )
            }
            rot.verifiedBootHash?.let {
                items.add(
                    InfoItem(
                        "Verified Boot Hash",
                        it,
                        indentLevel = 2
                    )
                )
            }
            rot.verifiedBootKey?.let {
                items.add(
                    InfoItem(
                        "Verified Boot Key",
                        it,
                        indentLevel = 2
                    )
                )
            }
        }
        props.osVersion?.let { items.add(InfoItem("OS Version", it.toString(), indentLevel = 1)) }
        props.osPatchLevel?.let {
            items.add(
                InfoItem(
                    "OS Patch Level",
                    it.toString(),
                    indentLevel = 1
                )
            )
        }
        props.attestationIdBrand?.let {
            items.add(
                InfoItem(
                    "Attestation ID Brand",
                    it,
                    indentLevel = 1
                )
            )
        }
        props.attestationIdDevice?.let {
            items.add(
                InfoItem(
                    "Attestation ID Device",
                    it,
                    indentLevel = 1
                )
            )
        }
        props.attestationIdProduct?.let {
            items.add(
                InfoItem(
                    "Attestation ID Product",
                    it,
                    indentLevel = 1
                )
            )
        }
        props.attestationIdSerial?.let {
            items.add(
                InfoItem(
                    "Attestation ID Serial",
                    it,
                    indentLevel = 1
                )
            )
        }
        props.attestationIdImei?.let {
            items.add(
                InfoItem(
                    "Attestation ID IMEI",
                    it,
                    indentLevel = 1
                )
            )
        }
        props.attestationIdMeid?.let {
            items.add(
                InfoItem(
                    "Attestation ID MEID",
                    it,
                    indentLevel = 1
                )
            )
        }
        props.attestationIdManufacturer?.let {
            items.add(
                InfoItem(
                    "Attestation ID Manufacturer",
                    it,
                    indentLevel = 1
                )
            )
        }
        props.attestationIdModel?.let {
            items.add(
                InfoItem(
                    "Attestation ID Model",
                    it,
                    indentLevel = 1
                )
            )
        }
        props.vendorPatchLevel?.let {
            items.add(
                InfoItem(
                    "Vendor Patch Level",
                    it.toString(),
                    indentLevel = 1
                )
            )
        }
        props.bootPatchLevel?.let {
            items.add(
                InfoItem(
                    "Boot Patch Level",
                    it.toString(),
                    indentLevel = 1
                )
            )
        }
        props.deviceUniqueAttestation?.let {
            items.add(
                InfoItem(
                    "Device Unique Attestation",
                    it.toString(),
                    indentLevel = 1
                )
            )
        }
        props.attestationIdSecondImei?.let {
            items.add(
                InfoItem(
                    "Attestation ID Second IMEI",
                    it,
                    indentLevel = 1
                )
            )
        }
        props.moduleHash?.let { items.add(InfoItem("Module Hash", it, indentLevel = 1)) }
    }

    private fun addCertificateChainInfo(
        items: MutableList<InfoItem>,
        certificateChain: List<CertificateDetails>
    ) {
        items.add(InfoItem(context.getString(R.string.header_certificate_chain), "", isHeader = true, indentLevel = 0))
        certificateChain.forEachIndexed { index, certDetails ->
            items.add(
                InfoItem(
                    "Certificate[${index}]",
                    "",
                    isHeader = true,
                    indentLevel = 1
                )
            )
            certDetails.name?.let { items.add(InfoItem("Name", it, indentLevel = 2)) }
            certDetails.serialNumber?.let { items.add(InfoItem("Serial Number", it, indentLevel = 2)) }
            certDetails.validFrom?.let { items.add(InfoItem("Valid From", it, indentLevel = 2)) }
            certDetails.validTo?.let { items.add(InfoItem("Valid To", it, indentLevel = 2)) }
            certDetails.signatureTypeSn?.let {
                items.add(
                    InfoItem(
                        "Signature Type SN",
                        it,
                        indentLevel = 2
                    )
                )
            }
            certDetails.signatureTypeLn?.let {
                items.add(
                    InfoItem(
                        "Signature Type LN",
                        it,
                        indentLevel = 2
                    )
                )
            }
            certDetails.subjectKeyIdentifier?.let {
                items.add(
                    InfoItem(
                        "Subject Key Identifier",
                        it,
                        indentLevel = 2
                    )
                )
            }
            certDetails.authorityKeyIdentifier?.let {
                items.add(
                    InfoItem(
                        "Authority Key Identifier",
                        it,
                        indentLevel = 2
                    )
                )
            }

            certDetails.keyUsage?.let { keyUsage ->
                val keyUsageItems = mutableListOf<InfoItem>()
                if (keyUsage.digitalSignature) keyUsageItems.add(
                    InfoItem(
                        "",
                        "Digital Signature",
                        indentLevel = 3
                    )
                )
                if (keyUsage.contentCommitment) keyUsageItems.add(
                    InfoItem(
                        "",
                        "Content Commitment",
                        indentLevel = 3
                    )
                )
                if (keyUsage.keyEncipherment) keyUsageItems.add(
                    InfoItem(
                        "",
                        "Key Encipherment",
                        indentLevel = 3
                    )
                )
                if (keyUsage.dataEncipherment) keyUsageItems.add(
                    InfoItem(
                        "",
                        "Data Encipherment",
                        indentLevel = 3
                    )
                )
                if (keyUsage.keyAgreement) keyUsageItems.add(
                    InfoItem(
                        "",
                        "Key Agreement",
                        indentLevel = 3
                    )
                )
                if (keyUsage.keyCertSign) keyUsageItems.add(
                    InfoItem(
                        "",
                        "Key Cert Sign",
                        indentLevel = 3
                    )
                )
                if (keyUsage.crlSign) keyUsageItems.add(
                    InfoItem(
                        "",
                        "CRL Sign",
                        indentLevel = 3
                    )
                )
                if (keyUsage.encipherOnly) keyUsageItems.add(
                    InfoItem(
                        "",
                        "Encipher Only",
                        indentLevel = 3
                    )
                )
                if (keyUsage.decipherOnly) keyUsageItems.add(
                    InfoItem(
                        "",
                        "Decipher Only",
                        indentLevel = 3
                    )
                )

                if (keyUsageItems.isNotEmpty()) {
                    items.add(InfoItem("Key Usage", "", isHeader = true, indentLevel = 2))
                    items.addAll(keyUsageItems)
                }
            }
        }
    }

    private fun convertDeviceInfoToAttestationItems(deviceInfo: DeviceInfo?): List<InfoItem> {
        deviceInfo ?: return emptyList()
        val items = mutableListOf<InfoItem>()
        items.add(
            InfoItem(
                context.getString(R.string.header_device_info),
                "",
                isHeader = true,
                indentLevel = 0
            )
        )
        items.add(InfoItem(context.getString(R.string.item_label_brand), deviceInfo.brand, indentLevel = 1))
        items.add(InfoItem(context.getString(R.string.item_label_model), deviceInfo.model, indentLevel = 1))
        items.add(InfoItem(context.getString(R.string.item_label_device), deviceInfo.device, indentLevel = 1))
        items.add(InfoItem(context.getString(R.string.item_label_product), deviceInfo.product, indentLevel = 1))
        items.add(InfoItem(context.getString(R.string.item_label_manufacturer), deviceInfo.manufacturer, indentLevel = 1))
        items.add(InfoItem(context.getString(R.string.item_label_hardware), deviceInfo.hardware, indentLevel = 1))
        items.add(InfoItem(context.getString(R.string.item_label_board), deviceInfo.board, indentLevel = 1))
        items.add(InfoItem(context.getString(R.string.item_label_bootloader), deviceInfo.bootloader, indentLevel = 1))
        items.add(InfoItem(context.getString(R.string.item_label_version_release), deviceInfo.versionRelease, indentLevel = 1))
        items.add(InfoItem(context.getString(R.string.item_label_sdk_int), deviceInfo.sdkInt.toString(), indentLevel = 1))
        items.add(InfoItem(context.getString(R.string.item_label_fingerprint), deviceInfo.fingerprint, indentLevel = 1))
        items.add(InfoItem(context.getString(R.string.item_label_security_patch), deviceInfo.securityPatch, indentLevel = 1))
        return items
    }

    private fun convertSecurityInfoToAttestationItems(securityInfo: SecurityInfo?): List<InfoItem> {
        securityInfo ?: return emptyList()
        val items = mutableListOf<InfoItem>()
        items.add(
            InfoItem(
                context.getString(R.string.header_security_info),
                "",
                isHeader = true,
                indentLevel = 0
            )
        )
        items.add(
            InfoItem(
                context.getString(R.string.item_label_device_lock_enabled),
                securityInfo.isDeviceLockEnabled.toString(),
                indentLevel = 1
            )
        )
        items.add(
            InfoItem(
                context.getString(R.string.item_label_biometrics_enabled),
                securityInfo.isBiometricsEnabled.toString(),
                indentLevel = 1
            )
        )
        items.add(
            InfoItem(
                context.getString(R.string.item_label_class_3_authenticator),
                securityInfo.hasClass3Authenticator.toString(),
                indentLevel = 1
            )
        )
        items.add(
            InfoItem(
                context.getString(R.string.item_label_strongbox),
                securityInfo.hasStrongbox.toString(),
                indentLevel = 1
            )
        )
        return items
    }
}

private object LocalValueConverter {
    fun convertSecurityLevelToString(value: Int): String {
        return when (value) {
            0 -> "Software(0)"
            1 -> "TrustedEnvironment(1)"
            2 -> "StrongBox(2)"
            else -> value.toString()
        }
    }

    fun convertVerifiedBootStateToString(value: Int): String {
        return when (value) {
            0 -> "Verified(0)"
            1 -> "SelfSigned(1)"
            2 -> "Unverified(2)"
            3 -> "Failed(3)"
            else -> value.toString()
        }
    }

    fun convertAlgorithmToString(value: Int): String {
        return when (value) {
            1 -> "RSA(1)"
            3 -> "EC(3)"
            32 -> "AES(32)"
            33 -> "TripleDES(33)"
            128 -> "HMAC(128)"
            else -> value.toString()
        }
    }

    fun convertPurposeToString(value: Int): String {
        return when (value) {
            0 -> "ENCRYPT(0)"
            1 -> "DECRYPT(1)"
            2 -> "SIGN(2)"
            3 -> "VERIFY(3)"
            5 -> "WRAP_KEY(5)"
            6 -> "AGREE_KEY(6)"
            7 -> "ATTEST_KEY(7)"
            else -> value.toString()
        }
    }

    fun convertOriginToString(value: Int): String {
        return when (value) {
            0 -> "GENERATED(0)"
            1 -> "DERIVED(1)"
            2 -> "IMPORTED(2)"
            else -> value.toString()
        }
    }

    fun convertEcCurveToString(value: Int): String {
        return when (value) {
            0 -> "P_224(0)"
            1 -> "P_256(1)"
            2 -> "P_384(2)"
            3 -> "P_521(3)"
            4 -> "CURVE_25519(4)"
            else -> value.toString()
        }
    }

    fun convertPaddingToString(value: Int): String {
        return when (value) {
            1 -> "NONE(1)"
            2 -> "RSA_OAEP(2)"
            3 -> "RSA_PSS(3)"
            4 -> "RSA_PKCS1_1_5_ENCRYPT(4)"
            5 -> "RSA_PKCS1_1_5_SIGN(5)"
            64 -> "PKCS7(64)"
            else -> value.toString()
        }
    }

    fun convertDigestToString(value: Int): String {
        return when (value) {
            0 -> "NONE(0)"
            1 -> "MD5(1)"
            2 -> "SHA1(2)"
            3 -> "SHA2_224(3)"
            4 -> "SHA2_256(4)"
            5 -> "SHA2_384(5)"
            6 -> "SHA2_512(6)"
            else -> value.toString()
        }
    }
}
