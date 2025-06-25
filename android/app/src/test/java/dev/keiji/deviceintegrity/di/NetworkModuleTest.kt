package dev.keiji.deviceintegrity.di

import dagger.hilt.android.testing.HiltAndroidRule
import dagger.hilt.android.testing.HiltAndroidTest
import dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationVerifyApiClient
import dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityTokenVerifyApiClient
import dev.keiji.deviceintegrity.di.qualifier.KeyAttestation
import dev.keiji.deviceintegrity.di.qualifier.PlayIntegrity
import junit.framework.TestCase.assertEquals
import junit.framework.TestCase.assertNotNull
import okhttp3.OkHttpClient
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import retrofit2.Retrofit
import javax.inject.Inject

@HiltAndroidTest
@Config(application = dagger.hilt.android.testing.HiltTestApplication::class)
@RunWith(RobolectricTestRunner::class) // To enable Android framework classes if Hilt needs them for context etc.
class NetworkModuleTest {

    @get:Rule
    var hiltRule = HiltAndroidRule(this)

    @Inject
    lateinit var okHttpClient: OkHttpClient

    @Inject
    @PlayIntegrity
    lateinit var playIntegrityRetrofit: Retrofit

    @Inject
    @KeyAttestation
    lateinit var keyAttestationRetrofit: Retrofit

    @Inject
    lateinit var playIntegrityTokenVerifyApiClient: PlayIntegrityTokenVerifyApiClient

    @Inject
    lateinit var keyAttestationVerifyApiClient: KeyAttestationVerifyApiClient

    @Before
    fun setUp() {
        hiltRule.inject()
    }

    @Test
    fun testOkHttpClientIsInjected() {
        assertNotNull("OkHttpClient should not be null", okHttpClient)
    }

    @Test
    fun testPlayIntegrityRetrofitIsInjected() {
        assertNotNull("PlayIntegrity Retrofit should not be null", playIntegrityRetrofit)
        assertEquals("https://playintegrity.googleapis.com/", playIntegrityRetrofit.baseUrl().toString())
    }

    @Test
    fun testKeyAttestationRetrofitIsInjected() {
        assertNotNull("KeyAttestation Retrofit should not be null", keyAttestationRetrofit)
        assertEquals("https://keyattestation.googleapis.com/", keyAttestationRetrofit.baseUrl().toString())
    }

    @Test
    fun testPlayIntegrityTokenVerifyApiClientIsInjected() {
        assertNotNull("PlayIntegrityTokenVerifyApiClient should not be null", playIntegrityTokenVerifyApiClient)
    }

    @Test
    fun testKeyAttestationVerifyApiClientIsInjected() {
        assertNotNull("KeyAttestationVerifyApiClient should not be null", keyAttestationVerifyApiClient)
    }
}
