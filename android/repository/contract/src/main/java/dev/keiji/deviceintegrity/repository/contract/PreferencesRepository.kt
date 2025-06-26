package dev.keiji.deviceintegrity.repository.contract

import kotlinx.coroutines.flow.Flow

interface PreferencesRepository {
    val playIntegrityVerifyApiEndpointUrl: Flow<String>
    val keyAttestationVerifyApiEndpointUrl: Flow<String>
    suspend fun savePlayIntegrityVerifyApiEndpointUrl(url: String)
    suspend fun saveKeyAttestationVerifyApiEndpointUrl(url: String)
}
