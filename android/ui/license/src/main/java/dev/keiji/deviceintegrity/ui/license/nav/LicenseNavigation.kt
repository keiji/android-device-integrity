package dev.keiji.deviceintegrity.ui.license.nav

import android.content.Context
import android.content.Intent
import dev.keiji.deviceintegrity.ui.license.LicenseActivity
import dev.keiji.deviceintegrity.ui.nav.contract.NavGraphEntryPoint
import javax.inject.Inject

interface LicenseNavigation {
    fun navigateToLicense(context: Context)
}

class LicenseNavigationImpl @Inject constructor() : LicenseNavigation, NavGraphEntryPoint {
    override fun navigateToLicense(context: Context) {
        val intent = Intent(context, LicenseActivity::class.java)
        context.startActivity(intent)
    }

    override val route: String = "license" // Define a unique route if needed for graph navigation
}
