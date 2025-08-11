package no.idporten.validator.certificate.util;

import no.idporten.validator.certificate.api.CertificateValidationException;

import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.X509CRL;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Extension to DirectoryCrlCache that holds CRL file in memory for a short period to avoid
 * reading crl file from disk for each validation
 */
public class MemoryAndDiskCrlCache extends DirectoryCrlCache {

    private static final int DEFAULT_LIFTETIME_MEM_CACHE_MILLIS = 60000;
    private final int liftetimeMemCache;
    Map<String, CachedCRL> cache = new ConcurrentHashMap<>();

    public MemoryAndDiskCrlCache(Path folder) throws IOException {
        super(folder);
        this.liftetimeMemCache = DEFAULT_LIFTETIME_MEM_CACHE_MILLIS;
    }

    public MemoryAndDiskCrlCache(Path folder, int liftetimeMemCache) throws IOException {
        super(folder);
        this.liftetimeMemCache = liftetimeMemCache;
    }

    @Override
    public void set(String s, X509CRL x509CRL) {
        super.set(s, x509CRL);
    }

    @Override
    public X509CRL get(String s) throws CertificateValidationException {
        CachedCRL memCachedCrl = cache.get(s);
        if (memCachedCrl == null || memCachedCrl.isExpired()) {
            return retrieveFromDiskAndPutInMemCache(s);
        }
        return memCachedCrl.getCrl();

    }

    private X509CRL retrieveFromDiskAndPutInMemCache(String s) throws CertificateValidationException {
        X509CRL crl = super.get(s);
        if (crl != null) {
            cache.put(s, new CachedCRL(crl));
        }

        return crl;
    }

    private class CachedCRL {

        final long cacheTime;
        final X509CRL crl;

        public CachedCRL(X509CRL crl) {
            this.cacheTime = System.currentTimeMillis();
            this.crl = crl;
        }

        protected boolean isExpired() {
            return System.currentTimeMillis() > cacheTime + liftetimeMemCache;
        }

        protected X509CRL getCrl() {
            return crl;
        }
    }

}
