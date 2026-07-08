import org.gradle.accessors.dm.LibrariesForLibs

// Convention plugin for static analysis and formatting
plugins {
    java
    checkstyle
    id("com.diffplug.spotless")
    id("net.ltgt.errorprone")
    id("com.github.spotbugs")
}

// Precompiled script plugins can't use the `libs` accessor directly — pull it
// out of the extensions container the same way Gradle's plugin DSL would.
val libs = the<LibrariesForLibs>()

spotless {
    java {
        palantirJavaFormat(libs.versions.palantir.java.format.get())
        removeUnusedImports()
        trimTrailingWhitespace()
    }
}

dependencies {
    compileOnly(libs.findbugs.jsr305)
    compileOnly(libs.spotbugs.annotations)
    errorprone(libs.errorprone.core)
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.add("-Werror")
    dependsOn("spotlessApply")
}

spotbugs {
    ignoreFailures.set(false)
}

tasks.withType<com.github.spotbugs.snom.SpotBugsTask>().configureEach {
    reports.create("html") { required.set(true) }
    reports.create("xml") { required.set(false) }
}

checkstyle {
    toolVersion = libs.versions.checkstyle.tool.get()
    configDirectory.set(rootProject.layout.projectDirectory.dir("config/checkstyle"))
    isIgnoreFailures = false
    maxWarnings = 0
}
