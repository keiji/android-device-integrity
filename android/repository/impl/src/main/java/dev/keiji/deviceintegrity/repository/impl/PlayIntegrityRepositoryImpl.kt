package dev.keiji.deviceintegrity.repository.impl

import dev.keiji.deviceintegrity.api.playintegrity.CreateNonceRequest
import dev.keiji.deviceintegrity.api.DeviceInfo
import dev.keiji.deviceintegrity.api.playintegrity.NonceResponse
import dev.keiji.deviceintegrity.api.playintegrity.NonceResponseV2
import dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityTokenVerifyApiClient
import dev.keiji.deviceintegrity.api.SecurityInfo
import dev.keiji.deviceintegrity.api.playintegrity.ServerVerificationPayload
import dev.keiji.deviceintegrity.api.playintegrity.StandardVerifyRequest
import dev.keiji.deviceintegrity.api.playintegrity.VerifyTokenRequest
import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfo
import dev.keiji.deviceintegrity.repository.contract.PlayIntegrityRepository
import dev.keiji.deviceintegrity.repository.contract.exception.ServerException
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject

class PlayIntegrityRepositoryImpl @Inject constructor(
    private val playIntegrityTokenVerifyApiClient: PlayIntegrityTokenVerifyApiClient
) : PlayIntegrityRepository {

    override suspend fun verifyTokenStandard(
        integrityToken: String,
        sessionId: String,
        contentBinding: String,
        deviceInfo: DeviceInfo,
        securityInfo: SecurityInfo,
        googlePlayDeveloperServiceInfo: GooglePlayDeveloperServiceInfo?
    ): ServerVerificationPayload {
        return try {
            val request = StandardVerifyRequest(
                token = integrityToken,
                sessionId = sessionId,
                contentBinding = contentBinding,
                deviceInfo = deviceInfo,
                securityInfo = securityInfo,
                googlePlayDeveloperServiceInfo = googlePlayDeveloperServiceInfo
            )
            return playIntegrityTokenVerifyApiClient.verifyTokenStandard(request)
        } catch (e: HttpException) {
            throw ServerException(
                errorCode = e.code(),
                errorMessage = e.response()?.errorBody()
                    ?.string(), // Consider parsing error body if it's structured (e.g., JSON)
                cause = e
            )
        }
    }

    override suspend fun verifyTokenClassic(
        integrityToken: String,
        sessionId: String,
        deviceInfo: DeviceInfo,
        securityInfo: SecurityInfo,
        googlePlayDeveloperServiceInfo: GooglePlayDeveloperServiceInfo?
    ): ServerVerificationPayload {
        return try {
            val request = VerifyTokenRequest(
                token = integrityToken,
                sessionId = sessionId,
                deviceInfo = deviceInfo,
                securityInfo = securityInfo,
                googlePlayDeveloperServiceInfo = googlePlayDeveloperServiceInfo
            )
            return playIntegrityTokenVerifyApiClient.verifyTokenClassic(request)
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

    override suspend fun getNonce(sessionId: String): NonceResponse {
        return try {
            val request = CreateNonceRequest(sessionId = sessionId)
            playIntegrityTokenVerifyApiClient.getNonce(request)
        } catch (e: HttpException) {
            throw ServerException(
                errorCode = e.code(),
                errorMessage = e.response()?.errorBody()?.string(),
                cause = e
            )
        }
    }

    override suspend fun getNonceV2(): NonceResponseV2 {
        return try {
            playIntegrityTokenVerifyApiClient.getNonceV2()
        } catch (e: HttpException) {
            throw ServerException(
                errorCode = e.code(),
                errorMessage = e.response()?.errorBody()?.string(),
                cause = e
            )
        }
    }
}
