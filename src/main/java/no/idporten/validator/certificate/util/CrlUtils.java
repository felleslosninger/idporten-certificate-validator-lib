package no.idporten.validator.certificate.util;

import no.idporten.validator.certificate.api.CertificateValidationException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;

/**
 * Utilities for CRL i/o.
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

    public static X509CRL download(String url) throws CertificateValidationException {
        if (url != null && url.matches("http[s]{0,1}://.*")) {
            X509CRL crl = httpDownload(url);
            return crl;
        } else if (url != null && url.startsWith("ldap://")) {
            // Currently not supported.
            return null;
        }
        return null;
    }

    static X509CRL httpDownload(String url) throws CertificateValidationException {
        try {
            return load(URI.create(url).toURL().openStream());
        } catch (IOException | CRLException e) {
            throw new CertificateValidationException(String.format("Failed to download CRL '%s' (%s)", url, e.getMessage()), e);
        }
    }

}