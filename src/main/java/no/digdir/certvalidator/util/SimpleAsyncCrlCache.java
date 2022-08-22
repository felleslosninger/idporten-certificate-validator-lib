package no.digdir.certvalidator.util;

import lombok.extern.slf4j.Slf4j;

import java.net.URL;
import java.security.cert.X509CRL;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * In-memory implementation of CRL cache that attempts to load all CRLs in cache at scheduled intervals.
 */
public class SimpleAsyncCrlCache extends SimpleCrlCache {

    /**
     * Default interval for asynchronous cache refresh is 15 minutes
     */
    public static final long DEFAULT_LIFTETIME_MEM_CACHE_MILLIS = 15 * 60 * 1000;

    /**
     * Create an instance using default refresh interval.
     */
    public SimpleAsyncCrlCache() {
        this(DEFAULT_LIFTETIME_MEM_CACHE_MILLIS);
    }

    /**
     * Create an instance using provided refresh interval.
     *
     * @param refreshIntervalMillis refresh interval, ignored if not larger than 0
     */
    public SimpleAsyncCrlCache(long refreshIntervalMillis) {
        new Thread(
                new CacheUpdater(this, refreshIntervalMillis > 0 ? refreshIntervalMillis : DEFAULT_LIFTETIME_MEM_CACHE_MILLIS))
                .start();
    }

    /**
     * Runnable re-loading all CRLs in cache at configured refresh interval.  Logs a warning if a CRL fails.
     */
    @Slf4j
    static class CacheUpdater implements Runnable {

        private final SimpleCrlCache crlCache;
        private final long refhreshIntervalMillis;

        public CacheUpdater(SimpleCrlCache crlCache, long refhreshIntervalMillis) {
            this.crlCache = Objects.requireNonNull(crlCache);
            this.refhreshIntervalMillis = refhreshIntervalMillis;
        }

        @Override
        public void run() {
            try { // start slowly
                Thread.sleep(30 * 1000);
            } catch (InterruptedException e) {
            }
            log.info("Starting CRL cache update thread with interval {} milliseconds", refhreshIntervalMillis);
            while (true) {
                Set<String> crlDistributionPoints = new HashSet<>(crlCache.getUrls());
                for (String crlDistributionPoint : crlDistributionPoints) {
                    try {
                        X509CRL crl = CrlUtils.load(new URL(crlDistributionPoint).openStream());
                        crlCache.set(crlDistributionPoint, crl);
                        log.info("CRL downloaded from {}: CRL last updated by CA {}, CRL next update {}", crlDistributionPoint, crl.getThisUpdate(), crl.getNextUpdate());
                    } catch (Exception e) {
                        log.warn("Failed to fetch CRL from {}", crlDistributionPoint, e);
                    }
                }
                try {
                    Thread.sleep(refhreshIntervalMillis);
                } catch (InterruptedException e) {
                }
            }

        }
    }

}
