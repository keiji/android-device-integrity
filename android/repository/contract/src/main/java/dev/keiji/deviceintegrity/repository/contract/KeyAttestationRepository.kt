package dev.keiji.deviceintegrity.repository.contract

import dev.keiji.deviceintegrity.api.keyattestation.PrepareSignatureRequest
import dev.keiji.deviceintegrity.api.keyattestation.PrepareResponse
import dev.keiji.deviceintegrity.api.keyattestation.VerifySignatureRequest
import dev.keiji.deviceintegrity.api.keyattestation.VerifySignatureResponse
import dev.keiji.deviceintegrity.repository.contract.exception.ServerException
import java.io.IOException

interface KeyAttestationRepository {
    /**
     * Prepares the key attestation process by fetching a nonce and challenge from the server.
     * @param requestBody The request containing the session ID.
     * @return [PrepareResponse] containing the nonce and challenge.
     * @throws ServerException if the server returns an error (e.g., HTTP error codes).
     * @throws IOException if a network error occurs.
     * @throws Exception for other unexpected errors.
     */
    @Throws(ServerException::class, IOException::class)
    suspend fun prepareSignature(
        requestBody: PrepareSignatureRequest
    ): PrepareResponse

    /**
     * Verifies the key attestation signature with the server.
     * @param requestBody The request containing the signature, certificates, and device information.
     * @return [VerifySignatureResponse] indicating the result of the verification.
     * @throws ServerException if the server returns an error.
     * @throws IOException if a network error occurs.
     * @throws Exception for other unexpected errors.
     */
    @Throws(ServerException::class, IOException::class)
    suspend fun verifySignature(
        requestBody: VerifySignatureRequest
    ): VerifySignatureResponse
}
