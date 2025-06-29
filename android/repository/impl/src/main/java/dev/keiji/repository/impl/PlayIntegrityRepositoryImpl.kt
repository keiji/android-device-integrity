package dev.keiji.repository.impl

import dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationRequest
import dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationResponse
import dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationVerifyApiClient
import dev.keiji.deviceintegrity.api.playintegrity.CreateNonceRequest
import dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo
import dev.keiji.deviceintegrity.api.playintegrity.NonceResponse
import dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityTokenVerifyApiClient
import dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo
import dev.keiji.deviceintegrity.api.playintegrity.ServerVerificationPayload
import dev.keiji.deviceintegrity.api.playintegrity.StandardVerifyRequest
import dev.keiji.deviceintegrity.api.playintegrity.VerifyTokenRequest
import dev.keiji.repository.contract.PlayIntegrityRepository
import dev.keiji.repository.contract.exception.ServerException
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject

class PlayIntegrityRepositoryImpl @Inject constructor(
    private val keyAttestationVerifyApiClient: KeyAttestationVerifyApiClient,
    private val playIntegrityTokenVerifyApiClient: PlayIntegrityTokenVerifyApiClient
) : PlayIntegrityRepository {

    override suspend fun getIntegrityVerdictStandard(
        integrityToken: String,
        sessionId: String,
        contentBinding: String,
        deviceInfo: DeviceInfo,
        securityInfo: SecurityInfo
    ): ServerVerificationPayload {
        return try {
            val request = StandardVerifyRequest(
                token = integrityToken,
                sessionId = sessionId,
                contentBinding = contentBinding,
                deviceInfo = deviceInfo,
                securityInfo = securityInfo
            )
            playIntegrityTokenVerifyApiClient.verifyTokenStandard(request)
        } catch (e: HttpException) {
            throw ServerException(
                errorCode = e.code(),
                errorMessage = e.response()?.errorBody()?.string(), // Consider parsing error body if it's structured (e.g., JSON)
                cause = e
            )
        } catch (e: IOException) {
            // Re-throw other IOExceptions (network errors, etc.)
            throw e
        }
    }

    override suspend fun getIntegrityVerdictClassic(
        integrityToken: String,
        sessionId: String,
        deviceInfo: DeviceInfo,
        securityInfo: SecurityInfo
    ): ServerVerificationPayload {
        return try {
            val request = VerifyTokenRequest(
                token = integrityToken,
                sessionId = sessionId,
                deviceInfo = deviceInfo,
                securityInfo = securityInfo
            )
            playIntegrityTokenVerifyApiClient.verifyTokenClassic(request)
        } catch (e: HttpException) {
            throw ServerException(
                errorCode = e.code(),
                errorMessage = e.response()?.errorBody()?.string(),
                cause = e
            )
        } catch (e: IOException) {
            throw e
        }
    }

    override suspend fun prepareChallenge(sessionId: String): NonceResponse {
        return try {
            val request = CreateNonceRequest(sessionId = sessionId)
            playIntegrityTokenVerifyApiClient.getNonce(request)
        } catch (e: HttpException) {
            throw ServerException(
                errorCode = e.code(),
                errorMessage = e.response()?.errorBody()?.string(),
                cause = e
            )
        } catch (e: IOException) {
            throw e
        }
    }

    override suspend fun verifyClassicDeviceAttestation(
        challenge: String,
        attestationStatement: String
    ): KeyAttestationResponse {
        return try {
            val request = KeyAttestationRequest(
                attestationStatement = attestationStatement,
                challenge = challenge
            )
            keyAttestationVerifyApiClient.verifyAttestation(request)
        } catch (e: HttpException) {
            throw ServerException(
                errorCode = e.code(),
                errorMessage = e.response()?.errorBody()?.string(),
                cause = e
            )
        } catch (e: IOException) {
            throw e
        }
    }
}
