package dev.keiji.deviceintegrity.repository.impl

import android.content.Context
import androidx.datastore.core.CorruptionException
import androidx.datastore.core.DataStore
import androidx.datastore.core.Serializer
import androidx.datastore.dataStore
import com.google.protobuf.InvalidProtocolBufferException
import dev.keiji.deviceintegrity.repository.contract.PreferencesRepository
import dev.keiji.deviceintegrity.repository.impl.pb.UserPreferences
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import java.io.InputStream
import java.io.OutputStream
import javax.inject.Inject

// Made public for testing, or consider an internal constructor for testing module
val Context.userPreferencesStore: DataStore<UserPreferences> by dataStore(
    fileName = "user_prefs.pb",
    serializer = UserPreferencesSerializer
)

object UserPreferencesSerializer : Serializer<UserPreferences> {
    override val defaultValue: UserPreferences = UserPreferences.getDefaultInstance()

    override suspend fun readFrom(input: InputStream): UserPreferences {
        try {
            return UserPreferences.parseFrom(input)
        } catch (exception: InvalidProtocolBufferException) {
            throw CorruptionException("Cannot read proto.", exception)
        }
    }

    override suspend fun writeTo(t: UserPreferences, output: OutputStream) = t.writeTo(output)
}

class PreferencesRepositoryImpl @Inject internal constructor( // internal constructor for testing
    private val dataStore: DataStore<UserPreferences>
) : PreferencesRepository {

    constructor(context: Context) : this(context.userPreferencesStore)

    override val firstLaunchDatetime: Flow<Long?> = dataStore.data
        .map { preferences ->
            if (preferences.firstLaunchDatetime == 0L) {
                null
            } else {
                preferences.firstLaunchDatetime
            }
        }

    override suspend fun saveFirstLaunchDatetime(datetime: Long) {
        dataStore.updateData { preferences ->
            preferences.toBuilder()
                .setFirstLaunchDatetime(datetime)
                .build()
        }
    }
}
