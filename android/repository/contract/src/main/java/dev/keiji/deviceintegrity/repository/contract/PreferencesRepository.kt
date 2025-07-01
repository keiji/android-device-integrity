package dev.keiji.deviceintegrity.repository.contract

import kotlinx.coroutines.flow.Flow

interface PreferencesRepository {
    val firstLaunchDatetime: Flow<Long?>
    suspend fun saveFirstLaunchDatetime(datetime: Long)
}
