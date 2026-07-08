# IAM Roles Anywhere Plugin for AWS SDK for Java

The IAM Roles Anywhere Plugin for AWS SDK for Java is an AWS SDK for Java v2 plugin for IAM Roles Anywhere. Sign requests with an X.509 certificate to obtain temporary AWS credentials, without long-term access keys.

## What Is IAM Roles Anywhere?

AWS IAM Roles Anywhere allows your workloads running outside of AWS (on-premises servers, containers, or other cloud environments) to obtain temporary AWS credentials by using X.509 certificates. This eliminates the need to store long-term AWS access keys in your applications.

## Most Common Use Case

**Scenario**: You have an application running on-premises or in another cloud that needs to access AWS services securely without embedding long-term credentials.

**Solution**: Add `RolesAnywherePlugin` to your AWS SDK clients. It calls IAM Roles Anywhere `CreateSession` and supplies temporary, auto-rotating AWS credentials.

## Quick Start

### Prerequisites

1. **Trust Anchor**: A root certificate authority (CA) or intermediate CA certificate registered with IAM Roles Anywhere
2. **Profile**: An IAM Roles Anywhere profile that defines which roles can be assumed
3. **Role**: An IAM role with the necessary permissions for your application
4. **Certificate**: An X.509 certificate signed by your registered CA
5. **Private Key**: The private key corresponding to your certificate

### Basic Usage

```java
import software.amazon.rolesanywhere.plugin.RolesAnywherePlugin;
import software.amazon.rolesanywhere.plugin.X509IdentityProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import java.nio.file.Paths;

// fromFiles re-reads the cert and key on every credential refresh, so on-disk
// rotation is picked up automatically without restarting the process.
RolesAnywherePlugin plugin = RolesAnywherePlugin.builder()
    .identityProvider(X509IdentityProvider.fromFiles(
        Paths.get("path/to/certificate.pem"),
        Paths.get("path/to/private-key.pem"),
        "RSA"))
    .trustAnchorArn("arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/12345678-1234-1234-1234-123456789012")
    .profileArn("arn:aws:rolesanywhere:us-east-1:123456789012:profile/12345678-1234-1234-1234-123456789012")
    .roleArn("arn:aws:iam::123456789012:role/MyApplicationRole")
    // .region(Region.US_EAST_1) // Optional - inferred from ARNs
    .build();

S3Client s3Client = S3Client.builder()
    .addPlugin(plugin)
    .region(Region.US_EAST_1)
    .build();

s3Client.listBuckets();
```

Adding the plugin to a non-AWS SDK client throws `IllegalStateException` at configuration time.

If the SDK client already has a `credentialsProvider` configured, the plugin
composes with it via `AwsCredentialsProviderChain` — the customer's provider
is tried first, and `RolesAnywhereCredentialsProvider` is the fallback. The
plugin never silently overwrites explicit customer configuration.

## Choosing an X509IdentityProvider

Pick one of the pre-built factories for the common cases; implement
`resolve()` yourself only when the certificate + key come from a dynamic
backend.

| Factory | When to use |
|---------|-------------|
| `X509IdentityProvider.fromFiles(cert, key, alg)` | Certificate and PKCS#8 key on local disk. Re-read on every refresh so on-disk rotation is picked up automatically. |
| `X509IdentityProvider.fromFiles(cert, key, alg, password)` | Same, for password-protected PKCS#8 keys. |
| `X509IdentityProvider.fromFiles(cert, key, alg, chain)` | Same, with a separate intermediate chain file. |
| `X509IdentityProvider.fromFiles(cert, key, alg, chain, password)` | Password-protected key with intermediate chain. |
| `X509IdentityProvider.ofStatic(identity)` | Identity is embedded/static (tests, HSM handles built once). Same object reused every refresh; the private key is never destroyed. |
| Custom `resolve()` lambda | Fetching from Secrets Manager, Parameter Store, S3, ACM PCA, KeyStore/PKCS#11, or any dynamic source. Combine with `X509Identity.fromPem(...)` if the source returns PEM strings. |

### Complete Example with Certificate Loading

```java
import software.amazon.rolesanywhere.plugin.RolesAnywherePlugin;
import software.amazon.rolesanywhere.plugin.X509IdentityProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;

import java.nio.file.Paths;

public class RolesAnywhereExample {

    public static void main(String[] args) throws Exception {
        RolesAnywherePlugin plugin = RolesAnywherePlugin.builder()
            .identityProvider(X509IdentityProvider.fromFiles(
                Paths.get("client-cert.pem"),
                Paths.get("client-key.pem"),
                "RSA"))
            .trustAnchorArn("arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/ta-12345")
            .profileArn("arn:aws:rolesanywhere:us-east-1:123456789012:profile/profile-12345")
            .roleArn("arn:aws:iam::123456789012:role/MyRole")
            .roleSessionName("MyApplication")
            .durationSeconds(3600) // 1 hour
            // No need to specify .region() - inferred from ARNs
            .build();

        // Add it to AWS clients
        S3Client s3 = S3Client.builder()
            .addPlugin(plugin)
            .build();

        // Make API calls
        s3.listBuckets().buckets().forEach(bucket ->
            System.out.println("Bucket: " + bucket.name()));
    }
}
```

## Configuration Options

### Required Parameters

- **identityProvider**: `X509IdentityProvider` that supplies the certificate and private key on every credential refresh
- **trustAnchorArn**: ARN of the trust anchor registered in IAM Roles Anywhere
- **profileArn**: ARN of the profile that defines role assumption rules
- **roleArn**: ARN of the IAM role to assume

### Optional Parameters

- **region**: AWS region (automatically inferred if not specified - see Region Resolution below)
- **roleSessionName**: Name for the role session (default: generated)
- **durationSeconds**: Duration of the AWS credentials session in seconds (900-43200, default: 3600)
- **endpoint**: Custom endpoint URI for testing or special configurations
- **fipsEnabled**: Use FIPS endpoints. `null` (default, unset — resolves to
  non-FIPS), `true`, or `false`. FIPS endpoints are only available in US
  regions and AWS GovCloud.
- **dualStackEnabled**: Use dual-stack IPv4/IPv6 endpoints. `null` (default,
  unset — resolves to non-dual-stack), `true`, or `false`.
- **httpClient**: Custom HTTP client
- **staleTime**: How early before AWS credential expiration to trigger a refresh. Defaults to 5 minutes.
- **minRefreshInterval**: Minimum interval between credential refresh cycles to prevent retry storms. Defaults to 5 minutes. Cannot be less than 30 seconds (use `Duration.ZERO` to disable).

### Region Resolution (Automatic)

The region parameter is **optional**. The provider automatically resolves the AWS region using this priority order:

1. **Explicitly set region** via `.region()` method
2. **System property**: `aws.region` system property
3. **Environment variable**: `AWS_REGION` environment variable
4. **ARN inference**: Extracted from trust anchor and profile ARNs (if both have the same region)
5. **Throw exception**: Couldn't identify desired region

This means you can often omit the region entirely:

```java
// Region will be automatically inferred from ARNs or environment
RolesAnywherePlugin plugin = RolesAnywherePlugin.builder()
    .identityProvider(X509IdentityProvider.ofStatic(identity))
    .trustAnchorArn("arn:aws:rolesanywhere:eu-west-1:123456789012:trust-anchor/ta-12345")
    .profileArn("arn:aws:rolesanywhere:eu-west-1:123456789012:profile/profile-12345")
    .roleArn("arn:aws:iam::123456789012:role/MyRole")
    // No .region() needed - will use eu-west-1 from ARNs
    .build();
```

## Direct Use of the Credentials Provider

The plugin is the recommended entry point. `RolesAnywhereCredentialsProvider` is also public, for cases where you need an `AwsCredentialsProvider` directly: calling `resolveCredentials()` outside an SDK client, or sharing one provider (and one session cache) across many clients.

```java
import software.amazon.rolesanywhere.plugin.RolesAnywhereCredentialsProvider;
import software.amazon.rolesanywhere.plugin.RolesAnywherePlugin;

RolesAnywhereCredentialsProvider provider = RolesAnywhereCredentialsProvider.builder()
    .identityProvider(X509IdentityProvider.ofStatic(identity))
    .trustAnchorArn(/* ... */)
    .profileArn(/* ... */)
    .roleArn(/* ... */)
    .build();

// Use it directly...
AwsCredentials creds = provider.resolveCredentials();

// ...or wrap it in a plugin to share across clients
RolesAnywherePlugin plugin = RolesAnywherePlugin.create(provider);
S3Client s3 = S3Client.builder().addPlugin(plugin).build();
DynamoDbClient ddb = DynamoDbClient.builder().addPlugin(plugin).build();
```

One shared provider gives all clients a single `CreateSession` exchange and a single credential cache. Calling `RolesAnywherePlugin.builder()...build()` per client creates a separate provider (and cache) each time.

## Certificate Chain Support

For certificates signed by intermediate CAs, include the certificate chain:

```java
List<X509Certificate> intermediates = Arrays.asList(intermediateCert1, intermediateCert2);
X509Identity identity = X509Identity.create(leafCertificate, privateKey, intermediates);
```

## Using with AWS Private CA (ACM PCA)

For certificates issued by [AWS Private CA](https://docs.aws.amazon.com/privateca/latest/userguide/), implement `X509IdentityProvider.resolve()` to dynamically issue and load short-lived certificates. The private key stays in memory only during credential signing.

```java
import software.amazon.rolesanywhere.plugin.RolesAnywherePlugin;
import software.amazon.rolesanywhere.plugin.X509Identity;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.acmpca.AcmPcaClient;
import software.amazon.awssdk.services.acmpca.model.*;
import software.amazon.awssdk.services.acmpca.waiters.AcmPcaWaiter;
import software.amazon.awssdk.regions.Region;

import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;

// Create the PCA client once — it holds no key material and is safe to reuse
AcmPcaClient pcaClient = AcmPcaClient.builder()
    .region(Region.US_EAST_1)
    .build();

// Build the plugin with ACM PCA-issued certificates
RolesAnywherePlugin plugin = RolesAnywherePlugin.builder()
    .identityProvider(() -> {
        try {
            // Generate a fresh key pair — private key stays local to this lambda
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Issue a short-lived certificate from ACM PCA (reuses shared client)
            IssueCertificateResponse issueResponse = pcaClient.issueCertificate(
                IssueCertificateRequest.builder()
                    .certificateAuthorityArn("arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/ca-id")
                    .csr(/* CSR built from keyPair.getPublic() */)
                    .signingAlgorithm("SHA256WITHRSA")
                    .validity(Validity.builder().value(1L).type(ValidityPeriodType.DAYS).build())
                    .build());

            // Wait for the certificate to be issued before retrieving it
            try (AcmPcaWaiter waiter = pcaClient.waiter()) {
                waiter.waitUntilCertificateIssued(
                    GetCertificateRequest.builder()
                        .certificateAuthorityArn("arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/ca-id")
                        .certificateArn(issueResponse.certificateArn())
                        .build());
            }

            GetCertificateResponse certResponse = pcaClient.getCertificate(
                GetCertificateRequest.builder()
                    .certificateAuthorityArn("arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/ca-id")
                    .certificateArn(issueResponse.certificateArn())
                    .build());

            return X509Identity.fromPem(
                certResponse.certificate(),
                pemEncode(keyPair.getPrivate()),
                "RSA");
        } catch (Exception e) {
            throw SdkClientException.create("Failed to issue certificate from ACM PCA", e);
        }
    })
    .trustAnchorArn("arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/ta-12345")
    .profileArn("arn:aws:rolesanywhere:us-east-1:123456789012:profile/profile-12345")
    .roleArn("arn:aws:iam::123456789012:role/MyRole")
    .minRefreshInterval(Duration.ofMinutes(2)) // Avoid hammering ACM PCA on transient failures
    .region(Region.US_EAST_1)
    .build();
```

This pattern:
- **Minimizes key exposure**: The private key is a local variable, eligible for GC after signing
- **Handles failures**: Wraps errors in `SdkClientException` so callers get a clear, unchecked signal
- **Prevents retry storms**: `minRefreshInterval` ensures ACM PCA isn't called more than once per interval even if credentials are expired

## Key Type Support

When loading private keys, you must specify the key algorithm type:

- **RSA keys**: Use `"RSA"` as the key type
- **Elliptic Curve keys**: Use `"EC"` as the key type
- **ML-DSA keys**: Use `"ML-DSA"` as the key type. ML-DSA requires a JCE provider such as BouncyCastle. The provider only needs to be registered once during application startup.

```java
// RSA
X509IdentityProvider rsa = X509IdentityProvider.fromFiles(
    Paths.get("rsa-cert.pem"), Paths.get("rsa-key.pem"), "RSA");

// EC
X509IdentityProvider ec = X509IdentityProvider.fromFiles(
    Paths.get("ec-cert.pem"), Paths.get("ec-key.pem"), "EC");

// ML-DSA — register a supporting JCE provider at application startup
Security.addProvider(new BouncyCastleProvider());
X509IdentityProvider mldsa = X509IdentityProvider.fromFiles(
    Paths.get("mldsa-cert.pem"), Paths.get("mldsa-key.pem"), "ML-DSA");
```

## Error Handling

The provider validates all inputs and throws descriptive exceptions:

- `IllegalArgumentException`: Invalid ARNs, missing required parameters
- `SdkClientException`: `X509IdentityProvider` failed (cert store unavailable, HSM error, IO), network errors, or invalid responses from AWS
- `SdkServiceException`: IAM Roles Anywhere returned an error response. Includes expired or otherwise invalid certificates (validated server-side as part of `CreateSession`)

## Security Best Practices

1. **Protect Private Keys**: Store private keys securely and never commit them to version control
2. **Certificate Rotation**: Implement regular certificate rotation
3. **Least Privilege**: Grant minimal necessary permissions to the IAM role
4. **Monitor Usage**: Use AWS CloudTrail to monitor credential usage
5. **Validate Certificates**: Ensure certificates are valid and not expired
6. **Private key lifecycle**: Every `X509Identity` carries an ownership bit
   that controls whether the plugin will call `PrivateKey.destroy()` on the
   key after each `CreateSession` signing. JCE providers that honor
   `Destroyable` (BouncyCastle, some HSM providers) will zero their internal
   secret state; JDK-bundled providers throw `DestroyFailedException`, which
   the plugin swallows at debug log level.
   - `X509Identity.create(cert, privateKey, ...)`,
     `X509Identity.fromPem(...)`, and `X509IdentityProvider.fromFiles(...)`
     are **plugin-owned**: the private key is destroyed after use. This is
     the safe default for keys loaded per refresh (disk, Secrets Manager,
     Parameter Store, dynamic ACM PCA issuance).
   - `X509Identity.createWithoutDestroyingKey(cert, privateKey, ...)` and
     `X509IdentityProvider.ofStatic(...)` are **caller-owned**: the plugin
     never destroys the key. Use these for HSM handles, PKCS#11 keys, or
     any key shared across other JCE consumers, where destroying would
     break the next refresh or another subsystem.

### A note on the test fixtures in this repo

The certificates and encrypted PKCS#8 keys under
`src/test/resources/certificates/` are **test-only fixtures** — locally
generated keys used to exercise parsing, decryption, and signing code
paths. They grant no access to any real system and must never be used in
production.

- Each fixture file is listed in `.gitallowed` at the repo root so secret
  scanners do not flag it as a leaked credential.
- See `src/test/resources/certificates/README.md` for full context and
  for instructions on regenerating the fixtures via
  `generate-encrypted-keys.sh`.

We chose to commit pre-generated fixtures rather than generate them from
a Gradle task at test time. Generating at test time would remove the keys
from the repository entirely, but it also requires `openssl` on every
build host and adds per-run latency to the test suite. Given that these
keys grant no access to anything, we considered the build-hermeticity
trade-off worth it.

## AWS Setup Requirements

### 1. Create Trust Anchor

**Method 1: Using JSON file (Recommended)**
```bash
# Create trust anchor JSON file
cat > trust-anchor.json << EOF
{
  "name": "MyTrustAnchor",
  "source": {
    "sourceType": "CERTIFICATE_BUNDLE",
    "sourceData": {
      "x509CertificateData": "$(cat ca-cert.pem | sed 's/$/\\n/' | tr -d '\n' | sed 's/\\n$//')"
    }
  },
  "enabled": true
}
EOF

# Create trust anchor
aws rolesanywhere create-trust-anchor \
    --cli-input-json file://trust-anchor.json \
    --region us-east-1
```

**Method 2: One-liner with jq**
```bash
aws rolesanywhere create-trust-anchor \
    --cli-input-json "$(jq -n --rawfile cert ca-cert.pem '{
      name: "MyTrustAnchor",
      source: {
        sourceType: "CERTIFICATE_BUNDLE",
        sourceData: {
          x509CertificateData: $cert
        }
      },
      enabled: true
    }')" \
    --region us-east-1
```

### 2. Create IAM Role
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "rolesanywhere.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

### 3. Create Profile
```bash
aws rolesanywhere create-profile \
    --name "MyProfile" \
    --role-arns "arn:aws:iam::123456789012:role/MyRole"
```

## Building and Testing

This is a Java library built with Gradle.

### Build Commands
```bash
# Build the library
./gradlew build

# Run tests
./gradlew test

# Run checkstyle on main code
./gradlew checkstyleMain

# Run checkstyle on test code
./gradlew checkstyleTest
```

### Dependencies
- AWS SDK for Java v2
- Java 8 or higher

## References

- [AWS IAM Roles Anywhere Documentation](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html)
- [AWS SDK for Java v2](https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/home.html)
- [X.509 Certificate Standards](https://tools.ietf.org/html/rfc5280)

## Development References

- [Gradle User Guide Command-Line Interface](https://docs.gradle.org/current/userguide/command_line_interface.html)
- [Gradle User Guide Java Plugin](https://docs.gradle.org/current/userguide/java_plugin.html)
- [Gradle User Guide Checkstyle Plugin](https://docs.gradle.org/current/userguide/checkstyle_plugin.html)
- [Gradle User Guide SpotBugs Plugin](http://spotbugs.readthedocs.io/en/latest/gradle.html)
- [Gradle User Guide JaCoCo Plugin](https://docs.gradle.org/current/userguide/jacoco_plugin.html)
- [JUnit5 Platform](https://junit.org/junit5/docs/current/user-guide/#running-tests-build-gradle)
