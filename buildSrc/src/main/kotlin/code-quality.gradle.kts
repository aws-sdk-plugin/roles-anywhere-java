// Convention plugin for static analysis and formatting
plugins {
    java
    id("com.diffplug.spotless")
    id("net.ltgt.errorprone")
    id("com.github.spotbugs")
}

spotless {
    java {
        palantirJavaFormat("2.89.0")
        removeUnusedImports()
        trimTrailingWhitespace()
    }
}

dependencies {
    compileOnly("com.google.code.findbugs:jsr305:3.0.2")
    compileOnly("com.github.spotbugs:spotbugs-annotations:4.9.0")
    errorprone("com.google.errorprone:error_prone_core:2.36.0")
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
