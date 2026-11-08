import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    application
}

repositories { mavenCentral() }

dependencies {
    implementation(project(":"))
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }

application {
    applicationName = "ehbp-adapter"
    mainClass.set("AdapterKt")
    // One JVM per fixture: favour startup over peak throughput.
    applicationDefaultJvmArgs = listOf("-XX:TieredStopAtLevel=1", "-Xshare:auto")
}
