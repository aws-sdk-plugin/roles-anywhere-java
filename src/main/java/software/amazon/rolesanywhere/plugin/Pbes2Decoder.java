package software.amazon.rolesanywhere.plugin;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import software.amazon.awssdk.annotations.SdkInternalApi;

/**
 * Decrypts PBES2-encrypted PKCS#8 private keys (RFC 8018).
 *
 * <p>Two modes of operation:</p>
 * <ul>
 *   <li><b>Explicit algorithm</b> — caller provides the JCE algorithm name
 *       (e.g. {@code "PBEWithHmacSHA384AndAES_128"}). No ASN.1 parsing needed.
 *       Works with any registered JCE provider including BouncyCastle for scrypt.</li>
 *   <li><b>Auto-detect</b> — resolves the algorithm name from the PBES2 ASN.1
 *       structure, then delegates to the explicit path. Supports PBKDF2 with
 *       HMAC-SHA256/384/512 and AES-128/192/256-CBC. scrypt requires a JCE
 *       provider such as BouncyCastle.</li>
 * </ul>
 */
@SdkInternalApi
final class Pbes2Decoder {

    private static final String OID_PBES2 = "1.2.840.113549.1.5.13";
    private static final String OID_PBKDF2 = "1.2.840.113549.1.5.12";
    private static final String OID_SCRYPT = "1.3.6.1.4.1.11591.4.11";

    private static final Map<String, String> PRF_OID_TO_HMAC = Map.of(
            "1.2.840.113549.2.7", "HmacSHA1",
            "1.2.840.113549.2.9", "HmacSHA256",
            "1.2.840.113549.2.10", "HmacSHA384",
            "1.2.840.113549.2.11", "HmacSHA512");

    private static final Map<String, String> CIPHER_OID_TO_NAME = Map.of(
            "2.16.840.1.101.3.4.1.2", "AES_128",
            "2.16.840.1.101.3.4.1.22", "AES_192",
            "2.16.840.1.101.3.4.1.42", "AES_256");

    private Pbes2Decoder() {}

    /**
     * Decrypt using an explicit JCE algorithm name. No ASN.1 parsing needed.
     *
     * @param der       DER-encoded EncryptedPrivateKeyInfo
     * @param password  decryption password (caller should zero after use)
     * @param keyType   key algorithm (e.g. "RSA", "EC")
     * @param algorithm JCE algorithm (e.g. "PBEWithHmacSHA256AndAES_256")
     * @return decrypted PrivateKey
     */
    public static PrivateKey decrypt(byte[] der, char[] password, String keyType, String algorithm)
            throws GeneralSecurityException, IOException {
        try {
            EncryptedPrivateKeyInfo encInfo = new EncryptedPrivateKeyInfo(der);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm);
            Cipher cipher = Cipher.getInstance(algorithm);
            PBEKeySpec keySpec = new PBEKeySpec(password);
            try {
                cipher.init(Cipher.DECRYPT_MODE, skf.generateSecret(keySpec), encInfo.getAlgParameters());
            } finally {
                keySpec.clearPassword();
            }
            return KeyFactory.getInstance(keyType).generatePrivate(encInfo.getKeySpec(cipher));
        } catch (InvalidKeySpecException e) {
            throw new GeneralSecurityException("Failed to decrypt private key — wrong password" + " or key type?", e);
        }
    }

    /**
     * Decrypt by auto-detecting the algorithm from PBES2 ASN.1 params.
     * Resolves the JCE algorithm name, then delegates to
     * {@link #decrypt(byte[], char[], String, String)}.
     *
     * @param der      DER-encoded EncryptedPrivateKeyInfo
     * @param password decryption password (caller should zero after use)
     * @param keyType  key algorithm (e.g. "RSA", "EC")
     * @return decrypted PrivateKey
     */
    public static PrivateKey decrypt(byte[] der, char[] password, String keyType)
            throws GeneralSecurityException, IOException {
        // Try JDK's built-in resolution first
        try {
            EncryptedPrivateKeyInfo encInfo = new EncryptedPrivateKeyInfo(der);
            String algName = encInfo.getAlgName();
            SecretKeyFactory.getInstance(algName); // probe availability
            return decrypt(der, password, keyType, algName);
        } catch (IOException | NoSuchAlgorithmException ignored) {
            // JDK couldn't parse or doesn't have the algorithm — fall through
        }

        String algorithm;
        try {
            algorithm = resolveAlgorithmName(der);
        } catch (IOException e) {
            throw new GeneralSecurityException(
                    "Failed to parse encrypted key — is this a PBES2 " + "encrypted PKCS#8 file?", e);
        }
        try {
            return decrypt(der, password, keyType, algorithm);
        } catch (IOException e) {
            throw new GeneralSecurityException("Failed to decrypt key with algorithm " + algorithm, e);
        }
    }

    /**
     * Parse PBES2 ASN.1 to resolve the JCE algorithm name.
     * Maps KDF + cipher OIDs to {@code PBEWith<PRF>And<Cipher>} format.
     */
    private static String resolveAlgorithmName(byte[] der) throws GeneralSecurityException, IOException {
        DerParser outer = new DerParser(der);
        DerParser seqParser = outer.readObject().getParser();
        DerParser algIdParser = seqParser.readObject().getParser();

        String pbes2Oid = algIdParser.readObject().getOid();
        if (!OID_PBES2.equals(pbes2Oid)) {
            throw new GeneralSecurityException("Not PBES2, OID: " + pbes2Oid);
        }

        DerParser pbes2Parser = algIdParser.readObject().getParser();
        DerParser kdfSeq = pbes2Parser.readObject().getParser();
        DerParser encSchemeParser = pbes2Parser.readObject().getParser();

        // Cipher OID
        String cipherOid = encSchemeParser.readObject().getOid();
        String cipherName = CIPHER_OID_TO_NAME.get(cipherOid);
        if (cipherName == null) {
            throw new GeneralSecurityException("Unsupported cipher OID: " + cipherOid);
        }
        if ("AES_192".equals(cipherName)) {
            throw new GeneralSecurityException("AES-192-CBC requires a JCE provider such as BouncyCastle. "
                    + "Register via Security.addProvider() or use "
                    + "loadPrivateKey(path, keyType, password, algorithm) "
                    + "with the provider's algorithm name.");
        }

        // KDF OID
        String kdfOid = kdfSeq.readObject().getOid();
        if (OID_SCRYPT.equals(kdfOid)) {
            throw new GeneralSecurityException("scrypt requires a JCE provider such as BouncyCastle. "
                    + "Register via Security.addProvider() or use "
                    + "loadPrivateKey(path, keyType, password, algorithm) "
                    + "with the provider's algorithm name.");
        }
        if (!OID_PBKDF2.equals(kdfOid)) {
            throw new GeneralSecurityException("Unsupported KDF OID: " + kdfOid);
        }

        // PRF from PBKDF2 params
        String hmacName = resolvePrf(kdfSeq);

        return "PBEWith" + hmacName + "And" + cipherName;
    }

    /**
     * Extract PRF algorithm from PBKDF2 params.
     * Handles optional keyLength INTEGER before PRF SEQUENCE.
     */
    private static String resolvePrf(DerParser kdfParser) throws GeneralSecurityException, IOException {
        DerParser params = kdfParser.readObject().getParser();
        params.readObject(); // salt
        params.readObject(); // iterations

        String hmacName = "HmacSHA1"; // default per RFC 8018
        while (params.hasNext()) {
            DerParser.Asn1Object obj = params.readObject();
            if (obj.isConstructed()) {
                String prfOid = obj.getParser().readObject().getOid();
                hmacName = PRF_OID_TO_HMAC.get(prfOid);
                if (hmacName == null) {
                    throw new GeneralSecurityException("Unsupported PRF OID: " + prfOid);
                }
            }
        }
        return hmacName;
    }
}
