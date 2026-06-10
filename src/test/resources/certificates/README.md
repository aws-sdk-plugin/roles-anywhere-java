# THESE ARE TEST-ONLY KEYS — DO NOT USE IN PRODUCTION

Every certificate and private key in this directory is a fixture used solely
by the unit test suite. The keys were generated locally with `openssl` (see
`generate-encrypted-keys.sh`) and are committed to source control so the
build is reproducible and offline-friendly.

**Do not:**

- Use these keys, or any key derived from them, to access real AWS accounts
  or any non-test system.
- Reference these paths from production configuration.
- Treat the password (`testpassword`) used for the encrypted PKCS#8 keys as
  sensitive — it exists only to exercise decryption code paths.

If you need a credential for a real workload, mint a fresh key pair and
follow the guidance in the top-level `README.md` (Security Best Practices).

## Why are these keys committed instead of generated at build time?

We considered generating these fixtures from a Gradle task on every test
run. We chose to commit them because:

- It removes `openssl` as a build-host requirement, keeping the build
  hermetic and runnable on minimal CI images.
- It eliminates per-run key-generation latency from the test suite.
- The keys are scoped to test fixtures only; they grant no access to any
  real system, so the usual "never commit private keys" rule does not
  apply here.

To regenerate the fixtures (e.g. to add a new cipher), run
`./generate-encrypted-keys.sh` from this directory.

## Secret scanners

These paths are listed in the repository-root `.gitallowed` file so that
secret scanners do not flag them as leaked credentials.
