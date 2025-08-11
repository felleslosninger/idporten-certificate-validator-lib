package no.idporten.validator.certificate.api;

import java.security.cert.X509CRL;

public interface CrlFetcher {
    X509CRL get(String url) throws CertificateValidationException;
}
