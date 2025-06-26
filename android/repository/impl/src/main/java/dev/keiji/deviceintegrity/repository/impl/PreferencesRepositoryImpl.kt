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
import javax.inject.Named
import dagger.hilt.android.qualifiers.ApplicationContext

// Made public for testing, or consider an internal constructor for testing module
val Context.userPreferencesStore: DataStore<UserPreferences> by dataStore(
    fileName = "user_prefs.pb",
    serializer = UserPreferencesSerializer
)

object UserPreferencesSerializer : Serializer<UserPreferences> {
    override val defaultValue: UserPreferences = UserPreferences.getDefaultInstance()

    override suspend fun readFrom(input: InputStream): UserPreferences {
        try {
            val parsed = UserPreferences.parseFrom(input)
            // Ensure that default values are applied if fields are missing
            return defaultValue.toBuilder().mergeFrom(parsed).build()
        } catch (exception: InvalidProtocolBufferException) {
            throw CorruptionException("Cannot read proto.", exception)
        }
    }

    override suspend fun writeTo(t: UserPreferences, output: OutputStream) = t.writeTo(output)
}

class PreferencesRepositoryImpl @Inject internal constructor(
    @ApplicationContext private val context: Context,
    private val dataStore: DataStore<UserPreferences>,
    @Named("PlayIntegrityBaseUrl") private val playIntegrityBaseUrl: String,
    @Named("KeyAttestationBaseUrl") private val keyAttestationBaseUrl: String
) : PreferencesRepository {

    override val playIntegrityVerifyApiEndpointUrl: Flow<String> = dataStore.data
        .map { preferences ->
            preferences.playIntegrityVerifyApiEndpointUrl.ifEmpty { playIntegrityBaseUrl }
        }

    override val keyAttestationVerifyApiEndpointUrl: Flow<String> = dataStore.data
        .map { preferences ->
            preferences.keyAttestationVerifyApiEndpointUrl.ifEmpty { keyAttestationBaseUrl }
        }

    override suspend fun savePlayIntegrityVerifyApiEndpointUrl(url: String) {
        dataStore.updateData { preferences ->
            preferences.toBuilder()
                .setPlayIntegrityVerifyApiEndpointUrl(url)
                .build()
        }
    }

    override suspend fun saveKeyAttestationVerifyApiEndpointUrl(url: String) {
        dataStore.updateData { preferences ->
            preferences.toBuilder()
                .setKeyAttestationVerifyApiEndpointUrl(url)
                .build()
        }
    }
}
