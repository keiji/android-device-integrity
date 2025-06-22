pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "Device Integrity"
include(":app")
include(
    ":provider:contract",
    ":provider:impl"
)
include(
    ":repository:contract",
    ":repository:impl"
)
include(
    ":ui:main",
    ":ui:theme"
)
include(":api")
