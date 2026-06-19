plugins {
    `kotlin-dsl`
}

repositories {
    gradlePluginPortal()
    mavenCentral()
}

dependencies {
    // Expose the type-safe `libs` accessor inside precompiled script plugins
    // (see code-quality.gradle.kts). This is the documented workaround for a
    // long-standing Gradle limitation.
    implementation(files(libs.javaClass.superclass.protectionDomain.codeSource.location))

    implementation(libs.spotless.plugin)
    implementation(libs.errorprone.plugin)
    implementation(libs.spotbugs.plugin)
}
