package software.amazon.rolesanywhere.plugin;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import software.amazon.awssdk.annotations.SdkInternalApi;

@SdkInternalApi
final class CertificateChainLoader {

    private CertificateChainLoader() {}

    static List<X509Certificate> load(Path chainPath) throws CertificateException, IOException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (InputStream in = Files.newInputStream(chainPath)) {
            List<X509Certificate> chain = new ArrayList<>();
            for (Certificate cert : factory.generateCertificates(in)) {
                chain.add((X509Certificate) cert);
            }
            return chain;
        }
    }
}
