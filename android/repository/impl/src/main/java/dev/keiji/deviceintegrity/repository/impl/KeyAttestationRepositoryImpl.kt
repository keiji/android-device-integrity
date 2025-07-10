package dev.keiji.deviceintegrity.repository.impl

import android.util.Log
import dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationVerifyApiClient
import dev.keiji.deviceintegrity.api.keyattestation.PrepareAgreementRequest
import dev.keiji.deviceintegrity.api.keyattestation.PrepareAgreementResponse
import dev.keiji.deviceintegrity.api.keyattestation.PrepareSignatureRequest
import dev.keiji.deviceintegrity.api.keyattestation.PrepareResponse
import dev.keiji.deviceintegrity.api.keyattestation.VerifySignatureRequest
import dev.keiji.deviceintegrity.api.keyattestation.VerifySignatureResponse
import dev.keiji.deviceintegrity.repository.contract.KeyAttestationRepository
import dev.keiji.deviceintegrity.repository.contract.exception.ServerException
import org.json.JSONObject
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject

class KeyAttestationRepositoryImpl @Inject constructor(
    private val apiClient: KeyAttestationVerifyApiClient
) : KeyAttestationRepository {

    companion object {
        private const val TAG = "KeyAttestationRepo"
    }

    @Throws(ServerException::class, IOException::class)
    override suspend fun prepareSignature(
        requestBody: PrepareSignatureRequest
    ): PrepareResponse {
        try {
            return apiClient.prepareSignature(requestBody)
        } catch (e: HttpException) {
            val errorBody = e.response()?.errorBody()?.string()
            val errorMessage = parseErrorMessage(errorBody)
            Log.w(TAG, "Prepare failed: HTTP ${e.code()}, Body: $errorBody", e)
            throw ServerException(errorCode = e.code(), errorMessage = errorMessage, cause = e)
        } catch (e: IOException) {
            Log.w(TAG, "Prepare failed: Network error", e)
            throw e // Re-throw IOException directly
        } catch (e: Exception) {
            Log.w(TAG, "Prepare failed: Unknown error", e)
            throw IOException("An unknown error occurred during prepare: ${e.message}", e) // Wrap unknown errors in IOException or a more generic custom one if available
        }
    }

    @Throws(ServerException::class, IOException::class)
    override suspend fun verifySignature(
        requestBody: VerifySignatureRequest
    ): VerifySignatureResponse {
        try {
            return apiClient.verifySignature(requestBody)
        } catch (e: HttpException) {
            val errorBody = e.response()?.errorBody()?.string()
            val errorMessage = parseErrorMessage(errorBody)
            Log.w(TAG, "VerifySignature failed: HTTP ${e.code()}, Body: $errorBody", e)
            throw ServerException(errorCode = e.code(), errorMessage = errorMessage, cause = e)
        } catch (e: IOException) {
            Log.w(TAG, "VerifySignature failed: Network error", e)
            throw e // Re-throw IOException directly
        } catch (e: Exception) {
            Log.w(TAG, "VerifySignature failed: Unknown error", e)
            throw IOException("An unknown error occurred during verifySignature: ${e.message}", e) // Wrap unknown errors
        }
    }

    @Throws(ServerException::class, IOException::class)
    override suspend fun prepareAgreement(
        requestBody: PrepareAgreementRequest
    ): PrepareAgreementResponse {
        try {
            return apiClient.prepareAgreement(requestBody)
        } catch (e: HttpException) {
            val errorBody = e.response()?.errorBody()?.string()
            val errorMessage = parseErrorMessage(errorBody)
            Log.w(TAG, "PrepareAgreement failed: HTTP ${e.code()}, Body: $errorBody", e)
            throw ServerException(errorCode = e.code(), errorMessage = errorMessage, cause = e)
        } catch (e: IOException) {
            Log.w(TAG, "PrepareAgreement failed: Network error", e)
            throw e // Re-throw IOException directly
        } catch (e: Exception) {
            Log.w(TAG, "PrepareAgreement failed: Unknown error", e)
            throw IOException("An unknown error occurred during prepareAgreement: ${e.message}", e) // Wrap unknown errors
        }
    }

    private fun parseErrorMessage(errorBody: String?): String? {
        errorBody ?: return null
        return try {
            val jsonObj = JSONObject(errorBody)
            // Try to get "message" or "error" field. If both are missing, optString returns empty string or null if key not found and no fallback.
            // Prefer non-empty message over error, then fallback to null if neither provides useful info.
            val message = jsonObj.optString("message", null)
            if (!message.isNullOrEmpty()) return message
            val error = jsonObj.optString("error", null)
            if (!error.isNullOrEmpty()) return error
            null // Return null if no meaningful message is found
        } catch (jsonE: Exception) {
            Log.w(TAG, "Failed to parse error JSON: $errorBody", jsonE)
            null
        }
    }
}
