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
    // One JVM per fixture: favour startup over peak throughput. The heap cap keeps
    // the reported RSS comparable to Go's true peak on --heavy runs: a streaming
    // client fits, a buffering one fails visibly instead of inflating young gen.
    applicationDefaultJvmArgs = listOf("-XX:TieredStopAtLevel=1", "-Xshare:auto", "-Xmx256m", "-XX:+UseSerialGC")
}
