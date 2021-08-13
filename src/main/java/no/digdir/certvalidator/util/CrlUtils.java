package no.digdir.certvalidator.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;

/**
 * @author erlend
 */
public class CrlUtils {

    private static CertificateFactory certificateFactory;

    static {
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    public static X509CRL load(InputStream inputStream) throws CRLException {
        return (X509CRL) certificateFactory.generateCRL(inputStream);
    }

    public static void save(OutputStream outputStream, X509CRL crl) throws CRLException, IOException {
        outputStream.write(crl.getEncoded());
    }
}