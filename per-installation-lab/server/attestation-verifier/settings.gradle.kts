pluginManagement { repositories { gradlePluginPortal(); google(); mavenCentral() } }
rootProject.name = "attestation-verifier"
include(":upstream")
project(":upstream").projectDir = file("../../.local/keyattestation")
