package dev.keiji.deviceintegrity.provider.impl

import android.content.Context
import android.content.pm.PackageManager
import com.google.android.gms.common.GooglePlayServicesUtil
import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfo
import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfoProvider
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import timber.log.Timber

class GooglePlayDeveloperServiceInfoProviderImpl(
    private val context: Context,
    private val ioDispatcher: CoroutineDispatcher,
) : GooglePlayDeveloperServiceInfoProvider {
    override suspend fun provide(): GooglePlayDeveloperServiceInfo? = withContext(ioDispatcher) {
        try {
            val packageManager = context.packageManager
            val packageName = GooglePlayServicesUtil.GOOGLE_PLAY_SERVICES_PACKAGE
            val packageInfo = packageManager.getPackageInfo(packageName, 0)

            val versionCode = packageInfo.longVersionCode
            val versionName = packageInfo.versionName ?: ""

            return@withContext GooglePlayDeveloperServiceInfo(
                versionCode = versionCode,
                versionName = versionName
            )
        } catch (e: PackageManager.NameNotFoundException) {
            Timber.w(e, "Google Play Services package not found.")
            return@withContext null
        } catch (e: Exception) {
            Timber.e(e, "Failed to get Google Play Services version info.")
            return@withContext null
        }
    }
}
