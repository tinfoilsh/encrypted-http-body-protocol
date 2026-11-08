pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}

rootProject.name = "ehbp"

// The conformance adapter is a subproject so one Gradle build (and one wrapper)
// covers the library and its CLI runner.
include(":adapter")
project(":adapter").projectDir = file("../conformance/adapters/kotlin")

// Android compile check: the same sources built as an Android library against
// minSdk 21. Only included when an Android SDK is available so the JVM build
// never depends on one. -PnoAndroid leaves it out regardless.
val sdkPresent = System.getenv("ANDROID_HOME") != null || System.getenv("ANDROID_SDK_ROOT") != null || file("local.properties").exists()
if (sdkPresent && !providers.gradleProperty("noAndroid").isPresent) {
    include(":android")
}
