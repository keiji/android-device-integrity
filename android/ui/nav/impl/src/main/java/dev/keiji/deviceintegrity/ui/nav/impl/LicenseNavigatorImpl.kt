package dev.keiji.deviceintegrity.ui.nav.impl

import android.content.Context
import android.content.Intent
import dev.keiji.deviceintegrity.ui.license.LicenseActivity
import dev.keiji.deviceintegrity.ui.nav.contract.LicenseNavigator
import javax.inject.Inject

class LicenseNavigatorImpl @Inject constructor() : LicenseNavigator {
    override fun newIntent(context: Context): Intent {
        return Intent(context, LicenseActivity::class.java)
    }
}
