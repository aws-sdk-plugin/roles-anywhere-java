plugins {
    `java-library`
    id("code-quality")
    id("publishing")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(platform("software.amazon.awssdk:bom:2.46.10"))
    implementation("software.amazon.awssdk:rolesanywhere:2.46.10")
    implementation("software.amazon.awssdk:apache-client:2.46.10")
    implementation("software.amazon.awssdk:auth:2.46.10")
    implementation("software.amazon.awssdk:http-auth-spi:2.46.10")
    implementation("software.amazon.awssdk:arns:2.46.10")
    implementation("software.amazon.awssdk:json-utils:2.46.10")

    implementation("org.apache.httpcomponents:httpclient:4.5.14")

    testImplementation("org.junit.jupiter:junit-jupiter:5.13.0")
    testImplementation("org.mockito:mockito-core:5.22.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.13.0")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
