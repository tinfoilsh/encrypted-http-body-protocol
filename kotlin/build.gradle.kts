import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.2.20"
    kotlin("android") version "2.2.20" apply false
    id("com.android.library") version "8.13.0" apply false
    `java-library`
}

group = "sh.tinfoil"
version = "0.5.0"

repositories { mavenCentral() }

// Shared by the JVM library and the Android compile check (android/).
val ehbpDependencies by extra(listOf(
    "org.bouncycastle:bcprov-jdk18on:1.79",
    "com.squareup.okhttp3:okhttp:4.12.0",
    "org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0",
))

dependencies {
    ehbpDependencies.forEach { api(it) }
    testImplementation(kotlin("test"))
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }

tasks.test { useJUnitPlatform() }

// Reproducible archives: fixed entry timestamps and order, so two clean builds
// of the same commit produce byte-identical jars (checked in CI).
tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}
