# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Bug Fixes

- Resolve ErrorProne and SpotBugs build failures

### Build

- Apply Gradle build system with Spotless formatting
- *(deps)* Bump actions/setup-java from 5.3.0 to 5.5.0 (#25)
- *(deps)* Bump software.amazon.awssdk:bom from 2.46.13 to 2.47.1 (#18)
- *(deps)* Bump gradle-wrapper from 9.5.1 to 9.6.1 (#6)
- *(deps)* Bump org.junit.platform:junit-platform-launcher (#7)
- *(deps)* Bump com.diffplug.spotless:spotless-plugin-gradle (#16)
- *(deps)* Bump org.junit.jupiter:junit-jupiter from 6.1.0 to 6.1.1 (#13)
- Produce byte-identical JARs for reproducible builds

### CI

- Add Dependabot for automated dependency updates
- Add git-secrets scan on push and pull_request

### Documentation

- *(build)* Correct stale Java 11 floor comment to Java 8
- *(plugin)* Move createDefaultHttpClient() Javadoc to its method
- *(contributing)* Document local git-secrets setup
- Generate CHANGELOG.md from commit log via git-cliff
- *(plugin)* Document throws contract on public API methods

### Features

- Add Java source implementation for IAM Roles Anywhere credentials

### Refactor

- *(plugin)* Harden review surface for first publish (#22)

### Tests

- *(plugin)* Suppress unchecked warning on IdentityProvider mock
- *(plugin)* Use Assumptions.assumeTrue for missing cert skip
- *(plugin)* Use assertNotEquals for resolveVersion fallback check


