package no.idporten.validator.certificate.util;

import no.idporten.validator.certificate.api.CertificateValidationException;
import no.idporten.validator.certificate.api.CrlCache;
import no.idporten.validator.certificate.api.CrlFetcher;

import java.security.cert.X509CRL;

/**
 * Simple implementation of CRL fetcher, which caches downloaded CRLs. If a CRL is not cached, or the Next update-
 * field of a cached CRL indicates there is an updated CRL available, an updated CRL will immediately be downloaded.
 */
public class SimpleCachingCrlFetcher implements CrlFetcher {

    protected CrlCache crlCache;

    public SimpleCachingCrlFetcher(CrlCache crlCache) {
        this.crlCache = crlCache;
    }

    @Override
    public X509CRL get(String url) throws CertificateValidationException {
        X509CRL crl = crlCache.get(url);
        if (crl == null) {
            // Not in cache
            crl = download(url);
        } else if (crl.getNextUpdate() != null && crl.getNextUpdate().getTime() < System.currentTimeMillis()) {
            // Outdated
            crl = download(url);
        } else if (crl.getNextUpdate() == null) {
            // No action.
        }
        return crl;
    }

    protected X509CRL download(String url) throws CertificateValidationException {
        return CrlUtils.download(url);
    }

}
