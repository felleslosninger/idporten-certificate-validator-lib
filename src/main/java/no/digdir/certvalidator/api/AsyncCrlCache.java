package no.digdir.certvalidator.api;

/**
 * Async CRL caches can update CRLs in the background. They can be started and stopped.
 */
public interface AsyncCrlCache extends CrlCache {

    /**
     * Starts the async handling of CRLs.
     */
    void start();

    /**
     * Stops the async handling of CRLs.
     */
    void stop();

}
