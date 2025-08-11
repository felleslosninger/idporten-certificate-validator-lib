package no.idporten.validator.certificate.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.X509CRL;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.*;

@DisplayName("When using a simple async crl cache")
public class SimpleAsyncCrlCacheTest {

    @Test
    @DisplayName("then the cache updater can be started and stopped")
    void testStopStartNeverRestart() throws Exception {
        String crlDistributionPoint1 = "http://crl.idporten.no/crl1";
        String crlDistributionPoint2 = "http://crl.idporten.no/crl2";
        // mock out the crl fetching
        SimpleAsyncCrlCache crlCache = new SimpleAsyncCrlCache(1L, 2 * 1000L);
        crlCache.set(crlDistributionPoint1, mock(X509CRL.class));
        crlCache.set(crlDistributionPoint2, mock(X509CRL.class));
        SimpleAsyncCrlCache.CacheUpdater cacheUpdater = spy(crlCache.getCacheUpdater());
        doReturn(mock(X509CRL.class)).when(cacheUpdater).download(anyString());
        crlCache.setCacheUpdater(cacheUpdater);

        // start the cache and wait a little
        crlCache.start();
        Thread.sleep(1 * 1000); // wait for slow start

        // stop the cache and check state
        crlCache.stop();
        assertFalse(crlCache.getCacheUpdater().isRunning());
        assertEquals(2, crlCache.getUrls().size());

        // wait a little and check no more downloads
        Thread.sleep(2 * 1000); // wait for slow stop
        verify(cacheUpdater, times(2)).download(anyString());

    }

}
