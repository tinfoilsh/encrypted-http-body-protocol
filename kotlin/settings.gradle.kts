pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
    // Declared here so AGP is only resolved when android/ is actually included;
    // a `plugins { ... apply false }` entry in the root build would fetch it for every build.
    plugins {
        kotlin("android") version "2.2.20"
        id("com.android.library") version "8.13.0"
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
