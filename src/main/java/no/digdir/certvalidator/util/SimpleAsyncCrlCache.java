package no.digdir.certvalidator.util;

import no.digdir.certvalidator.api.AsyncCrlCache;
import no.digdir.certvalidator.api.CertificateValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509CRL;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * In-memory implementation of CRL cache that attempts to load all CRLs in cache at scheduled intervals.
 */
public class SimpleAsyncCrlCache extends SimpleCrlCache implements AsyncCrlCache {

    private final Logger log = LoggerFactory.getLogger(SimpleAsyncCrlCache.class);

    /**
     * Default initial delay for asynchronous cache update is 30 seconds
     */
    public static final long DEFAULT_INIT_DELAY_MEM_CACHE_MILLIS = 30 * 1000;

    /**
     * Default interval for asynchronous cache refresh is 15 minutes
     */
    public static final long DEFAULT_LIFTETIME_MEM_CACHE_MILLIS = 15 * 60 * 1000;

    private CacheUpdater cacheUpdater;

    /**
     * Create an instance using default initial delay and refresh interval.
     */
    public SimpleAsyncCrlCache() {
        this(DEFAULT_INIT_DELAY_MEM_CACHE_MILLIS, DEFAULT_LIFTETIME_MEM_CACHE_MILLIS);
    }

    /**
     * Create an instance using default initial delay and provided refresh interval.
     */
    public SimpleAsyncCrlCache(long refreshIntervalMillis) {
        this(DEFAULT_INIT_DELAY_MEM_CACHE_MILLIS, refreshIntervalMillis);
    }

    /**
     * Create an instance using provided refresh interval.
     *
     * @param initialDelayMillis    initial delay for a relaxed start, ignored if not larger than 0
     * @param refreshIntervalMillis refresh interval, ignored if not larger than 0
     */
    public SimpleAsyncCrlCache(long initialDelayMillis, long refreshIntervalMillis) {
        this.cacheUpdater = new CacheUpdater(
                this,
                initialDelayMillis > 0 ? initialDelayMillis : DEFAULT_INIT_DELAY_MEM_CACHE_MILLIS,
                refreshIntervalMillis > 0 ? refreshIntervalMillis : DEFAULT_LIFTETIME_MEM_CACHE_MILLIS);
    }

    @Override
    public void set(String url, X509CRL crl) {
        super.set(url, crl);
        log.info("Cached CRL {}: CRL last updated {}, CRL next update {}", url, crl.getThisUpdate(), crl.getNextUpdate());
    }

    @Override
    public void start() {
        Thread t = new Thread(this.cacheUpdater, "CRLUpdater");
        t.setDaemon(true);
        t.start();
    }

    @Override
    public void stop() {
        this.cacheUpdater.stop();
    }

    protected CacheUpdater getCacheUpdater() {
        return this.cacheUpdater;
    }

    protected void setCacheUpdater(CacheUpdater cacheUpdater) {
        this.cacheUpdater = cacheUpdater;
    }

    /**
     * Runnable re-loading all CRLs in cache at configured refresh interval.  Logs a warning if a CRL fails.
     */
    static class CacheUpdater implements Runnable {

        private final Logger log = LoggerFactory.getLogger(CacheUpdater.class);
        private final SimpleAsyncCrlCache crlCache;
        private final long refhreshIntervalMillis;
        private final long initialDelayMillis;
        private boolean running;

        public CacheUpdater(SimpleAsyncCrlCache crlCache, long initialDelayMillis, long refhreshIntervalMillis) {
            this.crlCache = Objects.requireNonNull(crlCache);
            this.initialDelayMillis = initialDelayMillis;
            this.refhreshIntervalMillis = refhreshIntervalMillis;
            this.running = true;
        }

        public void stop() {
            this.running = false;
        }

        public boolean isRunning() {
            return this.running;
        }

        @Override
        public void run() {
            log.info("Starting CRL cache update thread with initial delay {} milliseconds and interval {} milliseconds", initialDelayMillis, refhreshIntervalMillis);
            try { // start slowly
                Thread.sleep(initialDelayMillis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            while (running) {
                Set<String> crlDistributionPoints = new HashSet<>(crlCache.getUrls());
                for (String crlDistributionPoint : crlDistributionPoints) {
                    try {
                        crlCache.set(crlDistributionPoint, download(crlDistributionPoint));
                    } catch (Exception e) {
                        log.warn("Failed to fetch CRL from {}", crlDistributionPoint, e);
                    }
                }
                try {
                    Thread.sleep(refhreshIntervalMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            log.info("Stopped CRL cache updater");
        }

        protected X509CRL download(String url) throws CertificateValidationException {
            return CrlUtils.download(url);
        }

    }

}
