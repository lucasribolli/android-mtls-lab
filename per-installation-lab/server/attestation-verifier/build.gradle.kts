plugins {
    kotlin("jvm") version "2.2.0"
    application
}
repositories { mavenCentral(); google() }
dependencies {
    implementation(project(":upstream"))
    implementation("com.google.code.gson:gson:2.11.0")
    implementation("com.google.protobuf:protobuf-javalite:4.28.3")
}
kotlin { jvmToolchain(21) }
application {
    mainClass.set("lab.verifier.MainKt")
    applicationDefaultJvmArgs = listOf("-Xmx256m")
}
