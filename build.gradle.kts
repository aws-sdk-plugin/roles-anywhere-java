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

// Pin the published bytecode floor to Java 17 to match what README documents
// and what CI builds with. Without an explicit `release` setting javac would
// target whatever the toolchain JDK is, silently bumping the floor on a
// toolchain change.
tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
