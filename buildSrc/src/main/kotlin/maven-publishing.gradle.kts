// Convention plugin for Maven Central publishing with GPG signing
plugins {
    `java-library`
    `maven-publish`
    signing
}

// Generate sources and javadoc JARs (required by Maven Central)
java {
    withSourcesJar()
    withJavadocJar()
}

// Suppress Javadoc warnings/errors that would fail the build
tasks.withType<Javadoc>().configureEach {
    (options as StandardJavadocDocletOptions).apply {
        addStringOption("Xdoclint:none", "-quiet")
        encoding = "UTF-8"
    }
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])

            // Coordinates default to project group/name/version from gradle.properties
            // but can be overridden here if needed

            pom {
                name = "AWS SDK Plugin for IAM Roles Anywhere"
                description = "AWS SDK for Java v2 plugin for IAM Roles Anywhere. Signs " +
                        "requests with an X.509 certificate to obtain temporary AWS credentials."
                url = "https://github.com/aws-sdk-plugins/roles-anywhere-java"
                inceptionYear = "2025"

                licenses {
                    license {
                        name = "The Apache License, Version 2.0"
                        url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
                    }
                }

                developers {
                    developer {
                        id = "aws"
                        name = "Amazon Web Services"
                        organization = "Amazon Web Services"
                        organizationUrl = "https://aws.amazon.com"
                    }
                }

                scm {
                    connection = "scm:git:git://github.com/aws-sdk-plugins/roles-anywhere-java.git"
                    developerConnection = "scm:git:ssh://github.com:aws-sdk-plugins/roles-anywhere-java.git"
                    url = "https://github.com/aws-sdk-plugins/roles-anywhere-java"
                }

                issueManagement {
                    system = "GitHub Issues"
                    url = "https://github.com/aws-sdk-plugins/roles-anywhere-java/issues"
                }
            }
        }
    }

    repositories {
        maven {
            name = "sonatype"
            // AWS SDK plugins publish through AWS's dedicated Sonatype instance.
            // Publishing to s01.oss.sonatype.org or oss.sonatype.org will fail for
            // namespaces containing "amazon" / "aws" — use aws.oss.sonatype.org.
            val releasesUrl = uri("https://aws.oss.sonatype.org/service/local/staging/deploy/maven2/")
            val snapshotsUrl = uri("https://aws.oss.sonatype.org/content/repositories/snapshots/")
            url = if (version.toString().endsWith("SNAPSHOT")) snapshotsUrl else releasesUrl

            credentials {
                username = findProperty("ossrhUsername") as String? ?: System.getenv("OSSRH_USERNAME")
                password = findProperty("ossrhPassword") as String? ?: System.getenv("OSSRH_PASSWORD")
            }
        }
    }
}

// Sign all publications - Maven Central requires GPG signatures
signing {
    // CI-friendly: support in-memory PGP keys via env vars or gradle properties.
    // Set these in ~/.gradle/gradle.properties or as environment variables:
    //   ORG_GRADLE_PROJECT_signingKeyId   (last 8 chars of key ID)
    //   ORG_GRADLE_PROJECT_signingKey     (ascii-armored private key)
    //   ORG_GRADLE_PROJECT_signingPassword
    //
    // For local dev with a keyring:
    //   signing.keyId=ABCD1234
    //   signing.secretKeyRingFile=/path/to/secring.gpg
    //   signing.password=<passphrase>

    val signingKeyId: String? = findProperty("signingKeyId") as String?
    val signingKey: String? = findProperty("signingKey") as String?
    val signingPassword: String? = findProperty("signingPassword") as String?

    if (signingKey != null) {
        // In-memory key (CI / env var path)
        if (signingKeyId != null) {
            useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
        } else {
            useInMemoryPgpKeys(signingKey, signingPassword)
        }
    }
    // else: falls back to gradle.properties signing.keyId / signing.secretKeyRingFile / signing.password

    sign(publishing.publications["mavenJava"])

    // Only require signing when actually publishing (not on every build)
    isRequired = gradle.taskGraph.hasTask("publish")
}
