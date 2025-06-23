package dev.keiji.deviceintegrity.ui.nav.impl

import android.app.Activity
import android.content.Context
import android.content.Intent
import androidx.activity.result.contract.ActivityResultContract
import dev.keiji.deviceintegrity.api_endpoint_settings.ApiEndpointSettingsActivity
import dev.keiji.deviceintegrity.ui.nav.contract.ApiEndpointSettingsNavigator

class ApiEndpointSettingsNavigatorImpl : ApiEndpointSettingsNavigator {
    override fun newIntent(context: Context): Intent {
        return Intent(context, ApiEndpointSettingsActivity::class.java)
    }

    override fun contract(): ActivityResultContract<Unit, Unit> {
        return object : ActivityResultContract<Unit, Unit>() {
            override fun createIntent(context: Context, input: Unit): Intent {
                return newIntent(context)
            }

            override fun parseResult(resultCode: Int, intent: Intent?) {
                // No result is expected.
            }
        }
    }
}
