package dev.keiji.deviceintegrity.ui.main

import android.os.Build
import com.google.common.truth.Truth.assertThat
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.util.ReflectionHelpers

@RunWith(RobolectricTestRunner::class)
class BottomNavigationTest {

    @Test
    fun testKeyAttestationTab_visible_on_Android_N_and_above() {
        // Test for Android N (API 24)
        ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", 24)
        var filteredItems = bottomNavigationItems.filter { screen ->
            screen != AppScreen.KeyAttestation || Build.VERSION.SDK_INT >= Build.VERSION_CODES.N
        }
        assertThat(filteredItems).contains(AppScreen.KeyAttestation)

        // Test for Android O (API 26) - example, version 25 would also work
        ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", 26)
        filteredItems = bottomNavigationItems.filter { screen ->
            screen != AppScreen.KeyAttestation || Build.VERSION.SDK_INT >= Build.VERSION_CODES.N
        }
        assertThat(filteredItems).contains(AppScreen.KeyAttestation)
    }

    @Test
    fun testKeyAttestationTab_hidden_below_Android_N() {
        // Test for Android M (API 23)
        ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", 23)
        var filteredItems = bottomNavigationItems.filter { screen ->
            screen != AppScreen.KeyAttestation || Build.VERSION.SDK_INT >= Build.VERSION_CODES.N
        }
        assertThat(filteredItems).doesNotContain(AppScreen.KeyAttestation)

        // Test for Android L (API 22)
        ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", 22)
        filteredItems = bottomNavigationItems.filter { screen ->
            screen != AppScreen.KeyAttestation || Build.VERSION.SDK_INT >= Build.VERSION_CODES.N
        }
        assertThat(filteredItems).doesNotContain(AppScreen.KeyAttestation)
    }
}
