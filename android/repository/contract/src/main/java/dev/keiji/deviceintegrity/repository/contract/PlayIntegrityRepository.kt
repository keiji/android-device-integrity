package dev.keiji.deviceintegrity.repository.contract

import dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationResponse
import dev.keiji.deviceintegrity.api.playintegrity.NonceResponse
import dev.keiji.deviceintegrity.api.playintegrity.ServerVerificationPayload
import dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo // For verifyToken methods if needed in request
import dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo // For verifyToken methods if needed in request
import dev.keiji.deviceintegrity.repository.contract.exception.ServerException

/**
 * Repository interface for Play Integrity API and classic integrity checks.
 */
interface PlayIntegrityRepository {

    /**
     * Decrypts and verifies the integrity verdict from Google Play (Standard API).
     * @param integrityToken The integrity token received from the Play Integrity API.
     * @param sessionId A unique identifier for the session.
     * @param contentBinding A binding for the request, e.g. hash of user action.
     * @param deviceInfo Information about the device.
     * @param securityInfo Information about the security status of the device.
     * @return [ServerVerificationPayload] containing the verdict details.
     * @throws ServerException if there is an issue communicating with the server or the server returns an error.
     * @throws java.io.IOException for other network or I/O related issues.
     */
    @Throws(ServerException::class, java.io.IOException::class)
    suspend fun verifyTokenStandard(
        integrityToken: String,
        sessionId: String,
        contentBinding: String,
        deviceInfo: DeviceInfo,
        securityInfo: SecurityInfo
    ): ServerVerificationPayload

    /**
     * Decrypts and verifies the integrity verdict from Google Play (Classic API).
     * @param integrityToken The integrity token received from the Play Integrity API.
     * @param sessionId A unique identifier for the session.
     * @param deviceInfo Information about the device.
     * @param securityInfo Information about the security status of the device.
     * @return [ServerVerificationPayload] containing the verdict details.
     * @throws ServerException if there is an issue communicating with the server or the server returns an error.
     * @throws java.io.IOException for other network or I/O related issues.
     */
    @Throws(ServerException::class, java.io.IOException::class)
    suspend fun verifyTokenClassic(
        integrityToken: String,
        sessionId: String,
        deviceInfo: DeviceInfo,
        securityInfo: SecurityInfo
    ): ServerVerificationPayload


    /**
     * Prepares a challenge (nonce) for classic integrity or Play Integrity API usage.
     * @param sessionId A unique identifier for the session.
     * @return [NonceResponse] containing the challenge.
     * @throws ServerException if there is an issue communicating with the server or the server returns an error.
     * @throws java.io.IOException for other network or I/O related issues.
     */
    @Throws(ServerException::class, java.io.IOException::class)
    suspend fun getNonce(
        sessionId: String
    ): NonceResponse
}
