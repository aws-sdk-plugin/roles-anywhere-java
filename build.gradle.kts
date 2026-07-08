plugins {
    `java-library`
    id("code-quality")
    id("maven-publishing")
}

repositories {
    mavenCentral()
}

dependencies {
    api(platform(libs.awssdk.bom))
    // Types that leak through this plugin's public surface — customers compile
    // against them when calling the Builder (Arn overloads) or consuming
    // resolveCredentials() (AwsCredentials).
    api(libs.awssdk.auth)
    api(libs.awssdk.arns)

    implementation(libs.awssdk.annotations)
    implementation(libs.awssdk.rolesanywhere)
    implementation(libs.awssdk.apache.client)
    implementation(libs.awssdk.http.auth.spi)
    implementation(libs.awssdk.json.utils)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.mockito.core)
    testRuntimeOnly(libs.junit.platform.launcher)
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

// Pin the published bytecode floor to Java 8 to match AWS SDK v2's minimum.
// The toolchain still runs on 17 for consistent CI; --release=8 caps the API
// surface and bytecode target.
tasks.named<JavaCompile>("compileJava") {
    options.release.set(8)
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

// Emit the resolved project version into a resource file so X509Signer can
// stamp it into the User-Agent at runtime. Read via the class loader, so the
// same lookup works from unit tests (build/resources/main) and from the
// published jar (META-INF/…).
val generatePluginVersionResource by tasks.registering {
    val outputDir = layout.buildDirectory.dir("generated/resources/version/META-INF")
    outputs.dir(outputDir)
    val versionValue = project.version.toString()
    inputs.property("version", versionValue)
    doLast {
        val dir = outputDir.get().asFile
        dir.mkdirs()
        dir.resolve("rolesanywhere-plugin-version.properties").writeText("version=$versionValue\n")
    }
}

sourceSets["main"].resources.srcDir(
    generatePluginVersionResource.map { layout.buildDirectory.dir("generated/resources/version") }
)
