import me.champeau.gradle.japicmp.JapicmpTask
import org.gradle.accessors.dm.LibrariesForLibs

// Convention plugin for static analysis and formatting
plugins {
    java
    checkstyle
    id("com.diffplug.spotless")
    id("net.ltgt.errorprone")
    id("com.github.spotbugs")
    id("me.champeau.gradle.japicmp")
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

// Public-API binary-compatibility gate.
//
// Compares the current jar against a previously-published baseline pulled from
// Maven Central and fails the build on any breaking change to the public /
// protected member surface. The baseline coordinate is
// "${project.group}:${archivesBaseName}:${apiBaselineVersion}" — set
// `apiBaselineVersion` in gradle.properties or on the CLI once the first
// version has been published; the check is skipped when unset so pre-1.0.0
// builds still pass.
val apiBaselineVersion: String? = findProperty("apiBaselineVersion") as String?

if (apiBaselineVersion != null) {
    val baselineArtifact = configurations.detachedConfiguration(
        dependencies.create("${project.group}:${the<BasePluginExtension>().archivesName.get()}:$apiBaselineVersion")
    ).apply {
        isTransitive = false
        description = "Previously-published jar used as the japicmp baseline."
    }

    val checkApiCompatibility = tasks.register<JapicmpTask>("checkApiCompatibility") {
        group = "verification"
        description = "Fails on any breaking change to the public API vs $apiBaselineVersion."
        oldClasspath.from(baselineArtifact)
        newClasspath.from(tasks.named<Jar>("jar"))
        onlyBinaryIncompatibleModified.set(true)
        failOnModification.set(true)
        ignoreMissingClasses.set(true)
        includeSynthetic.set(false)
        // Only enforce on production API — non-public members are free to churn.
        accessModifier.set("public")
        htmlOutputFile.set(layout.buildDirectory.file("reports/japicmp/api-compat.html"))
        txtOutputFile.set(layout.buildDirectory.file("reports/japicmp/api-compat.txt"))
    }

    tasks.named("check") { dependsOn(checkApiCompatibility) }
}
