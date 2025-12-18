package dev.keiji.deviceintegrity.ui.nav.impl

import android.content.Context
import android.content.Intent
import dev.keiji.deviceintegrity.ui.express_mode.ExpressModeActivity
import dev.keiji.deviceintegrity.ui.nav.contract.ExpressModeNavigator
import javax.inject.Inject

class ExpressModeNavigatorImpl @Inject constructor() : ExpressModeNavigator {
    override fun newIntent(context: Context): Intent {
        return Intent(context, ExpressModeActivity::class.java)
    }
}
