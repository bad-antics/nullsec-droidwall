plugins {
    kotlin("jvm") version "1.9.0"
    application
}

group = "com.nullsec"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    testImplementation(kotlin("test"))
}

kotlin {
    jvmToolchain(17)
}

application {
    mainClass.set("com.nullsec.droidwall.DroidWallKt")
}

tasks.jar {
    manifest {
        attributes["Main-Class"] = "com.nullsec.droidwall.DroidWallKt"
    }
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}
