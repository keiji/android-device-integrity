pluginManagement {
    repositories {
        gradlePluginPortal()
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        mavenLocal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        mavenLocal()
    }
}

rootProject.name = "Device Integrity"
include(":app")
include(
    ":provider:contract",
    ":provider:impl"
)
include(
    ":crypto:contract",
    ":crypto:impl"
)
include(
    ":repository:contract",
    ":repository:impl"
)
include(
    ":ui:main",
    ":ui:theme",
    ":ui:nav:contract",
    ":ui:nav:impl",
    ":ui:license",
    ":ui:agreement",
    ":ui:play-integrity",
    ":ui:key-attestation",
    ":ui:express-mode",
    ":ui:menu"
)
include(":api")
