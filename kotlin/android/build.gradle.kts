import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// Compiles the library sources as an Android library (minSdk 21) so an API that
// only exists on the JDK, or above minSdk, fails the build instead of an app.
// Unit tests stay in the JVM project; this module produces no tests of its own.
plugins {
    id("com.android.library")
    kotlin("android")
}

repositories {
    google()
    mavenCentral()
}

android {
    namespace = "sh.tinfoil.ehbp"
    compileSdk = 35
    defaultConfig { minSdk = 21 }
    sourceSets["main"].kotlin.srcDir("../src/main/kotlin")
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    lint {
        checkOnly += setOf("NewApi", "InlinedApi")
        warningsAsErrors = true
        abortOnError = true
    }
}

kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }

dependencies {
    @Suppress("UNCHECKED_CAST")
    (rootProject.extra["ehbpDependencies"] as List<String>).forEach { api(it) }
}
