package dev.keiji.deviceintegrity.repository.contract

import kotlinx.coroutines.flow.Flow

interface PreferencesRepository {
    val apiEndpointUrl: Flow<String?>
    suspend fun saveApiEndpointUrl(url: String)
}
