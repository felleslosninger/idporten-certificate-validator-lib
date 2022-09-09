package no.digdir.certvalidator.util;

import no.digdir.certvalidator.api.CertificateValidationException;
import no.digdir.certvalidator.api.CrlCache;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.X509CRL;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@DisplayName("When fetching and caching CRLs")
public class SimpleCachingCrlFetcherTest {

    @DisplayName("then a cache miss will trigger a download")
    @Test
    void testCacheMissTriggersDownload() throws CertificateValidationException {
        String crlDistributionPoint = "http://crl.idporten.no/crl1";
        X509CRL crl = mock(X509CRL.class);
        CrlCache crlCache = mock(CrlCache.class);
        SimpleCachingCrlFetcher crlFetcher = spy(new SimpleCachingCrlFetcher(crlCache));
        doReturn(crl).when(crlFetcher).download(eq(crlDistributionPoint));
        assertNotNull(crlFetcher.get(crlDistributionPoint));
        verify(crlCache).get(crlDistributionPoint);
    }

    @DisplayName("then an expired CRL will trigger a download")
    @Test
    void testExpiredCrlTriggersDownload() throws CertificateValidationException {
        String crlDistributionPoint = "http://crl.idporten.no/crl1";
        X509CRL crl = mock(X509CRL.class);
        SimpleCrlCache crlCache = new SimpleCrlCache();
        crlCache.set(crlDistributionPoint, crl);
        SimpleCachingCrlFetcher crlFetcher = spy(new SimpleCachingCrlFetcher(crlCache));
        doReturn(crl).when(crlFetcher).download(eq(crlDistributionPoint));
        assertNotNull(crlFetcher.get(crlDistributionPoint));
    }

    @DisplayName("then a non-expired cached CRL will be returned directly")
    @Test
    void testNonExpiredCachedCrlReturnedFromCache() throws CertificateValidationException {
        String crlDistributionPoint = "http://crl.idporten.no/crl1";
        X509CRL crl = mock(X509CRL.class);
        when(crl.getNextUpdate()).thenReturn(new Date(System.currentTimeMillis() + (60 * 60 * 1000)));
        SimpleCrlCache crlCache = new SimpleCrlCache();
        crlCache.set(crlDistributionPoint, crl);
        SimpleCachingCrlFetcher crlFetcher = spy(new SimpleCachingCrlFetcher(crlCache));
        assertEquals(crl, crlFetcher.get(crlDistributionPoint));
        verify(crlFetcher, never()).download(anyString());
    }

    @DisplayName("then an exception is thrown if a download fails")
    @Test
    void testFailedDownloadThrowsException() throws CertificateValidationException {
        String crlDistributionPoint = "http://crl.idporten.no/crl1";
        X509CRL crl = mock(X509CRL.class);
        when(crl.getNextUpdate()).thenReturn(new Date(System.currentTimeMillis() - (60 * 60 * 1000)));
        SimpleCrlCache crlCache = new SimpleCrlCache();
        crlCache.set(crlDistributionPoint, crl);
        SimpleCachingCrlFetcher crlFetcher = spy(new SimpleCachingCrlFetcher(crlCache));
        doThrow(new CertificateValidationException("test")).when(crlFetcher).download(eq(crlDistributionPoint));
        assertThrows(CertificateValidationException.class, () -> crlFetcher.get(crlDistributionPoint));
    }

}
