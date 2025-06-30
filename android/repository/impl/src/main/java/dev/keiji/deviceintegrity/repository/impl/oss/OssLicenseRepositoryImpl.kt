package dev.keiji.deviceintegrity.repository.impl.oss

import dev.keiji.deviceintegrity.repository.contract.oss.OssLicenseRepository
import dev.keiji.deviceintegrity.repository.contract.oss.PomInfo
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext

class OssLicenseRepositoryImpl(
    private val dispatcher: CoroutineDispatcher
) : OssLicenseRepository {
    override suspend fun loadLicenses(): List<PomInfo> = withContext(dispatcher) {
        // TODO: Implement actual license loading logic
        emptyList()
    }
}
