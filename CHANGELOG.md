# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-07-30

### CI

- *(release)* Disable japicmp for first-release build (#34)

## [1.0.0] - 2026-07-30

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
- *(api-compat)* Enforce public API stability with japicmp (#30)
- *(deps)* Bump actions/checkout from 7.0.0 to 7.0.1 (#27)
- *(deps)* Bump actions/setup-java from 5.5.0 to 5.6.0 (#28)
- *(deps)* Bump actions/checkout from 7.0.0 to 7.0.1 (#32)

### CI

- Add Dependabot for automated dependency updates
- Add gitleaks scan alongside git-secrets (#31)

### Documentation

- *(contributing)* Add Automated Tools AI-use policy (#29)

### Features

- Add Java source implementation for IAM Roles Anywhere credentials
- Add release workflow for v* tag → S3 staging upload (#33)

### Refactor

- *(plugin)* Harden review surface for first publish (#22)


