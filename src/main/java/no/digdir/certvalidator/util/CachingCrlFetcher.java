package no.digdir.certvalidator.util;

import no.digdir.certvalidator.api.CertificateValidationException;
import no.digdir.certvalidator.api.CrlCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509CRL;

/**
 * CrlFetcher that ignores problems with retrieving new CRL file,
 * and uses old crl file from cache
 */
public class CachingCrlFetcher extends SimpleCachingCrlFetcher {

    private static final Logger logger = LoggerFactory.getLogger(CachingCrlFetcher.class);

    public CachingCrlFetcher(CrlCache crlCache) {
        super(crlCache);
    }

    @Override
    public X509CRL get(String url) throws CertificateValidationException {
        X509CRL crl = this.crlCache.get(url);
        try {
            if (crl == null) {
                crl = super.download(url);
            } else if (crl.getNextUpdate() != null && crl.getNextUpdate().getTime() < System.currentTimeMillis()) {
                crl = super.download(url);
            }
        } catch (CertificateValidationException e) {
            logger.error("Failed to retrieve CRL list", e);
        }
        return crl;
    }

}
