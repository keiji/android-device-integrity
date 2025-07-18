package dev.keiji.deviceintegrity.repository.contract

// API model imports
import dev.keiji.deviceintegrity.api.keyattestation.PrepareAgreementResponse
import dev.keiji.deviceintegrity.api.keyattestation.PrepareResponse
import dev.keiji.deviceintegrity.api.keyattestation.VerifyAgreementRequest
import dev.keiji.deviceintegrity.api.keyattestation.VerifyAgreementResponse
import dev.keiji.deviceintegrity.api.keyattestation.VerifySignatureRequest
import dev.keiji.deviceintegrity.api.keyattestation.VerifySignatureResponse
// Local project imports
import dev.keiji.deviceintegrity.repository.contract.exception.ServerException
import java.io.IOException

interface KeyAttestationRepository {
    /**
     * Prepares the key attestation process by fetching a nonce and challenge from the server.
     * @return [PrepareResponse] containing the nonce and challenge.
     * @throws ServerException if the server returns an error (e.g., HTTP error codes).
     * @throws IOException if a network error occurs.
     * @throws Exception for other unexpected errors.
     */
    @Throws(ServerException::class, IOException::class)
    suspend fun prepareSignature(): PrepareResponse

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

    /**
     * Prepares the key agreement process by fetching a salt and challenge from the server.
     * @return [PrepareAgreementResponse] containing the salt and challenge.
     * @throws ServerException if the server returns an error (e.g., HTTP error codes).
     * @throws IOException if a network error occurs.
     * @throws Exception for other unexpected errors.
     */
    @Throws(ServerException::class, IOException::class)
    suspend fun prepareAgreement(): PrepareAgreementResponse

    /**
     * Verifies the key attestation agreement with the server.
     * @param requestBody The request containing the session ID, encrypted data, client public key, and device/security info.
     * @return [VerifySignatureResponse] indicating the result of the verification (reuses signature's response type).
     * @throws ServerException if the server returns an error.
     * @throws IOException if a network error occurs.
     * @throws Exception for other unexpected errors.
     */
    @Throws(ServerException::class, IOException::class)
    suspend fun verifyAgreement(
        requestBody: VerifyAgreementRequest
    ): VerifyAgreementResponse
}
