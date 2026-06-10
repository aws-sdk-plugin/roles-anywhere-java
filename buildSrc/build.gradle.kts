plugins {
    `kotlin-dsl`
}

repositories {
    gradlePluginPortal()
    mavenCentral()
}

dependencies {
    implementation("com.diffplug.spotless:spotless-plugin-gradle:7.0.2")
    implementation("net.ltgt.gradle:gradle-errorprone-plugin:4.1.0")
    implementation("com.github.spotbugs.snom:spotbugs-gradle-plugin:6.1.2")
}
