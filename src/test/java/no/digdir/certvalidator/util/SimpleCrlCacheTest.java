package no.digdir.certvalidator.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.X509CRL;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@DisplayName("When using a simple crl cache")
public class SimpleCrlCacheTest {

    @Test
    @DisplayName("then an empty cache does not know any CRL urls")
    void testEmptyCache() {
        assertTrue(new SimpleCrlCache().getUrls().isEmpty());
    }

    @Test
    @DisplayName("then all CRL urls is in the cache's set of known URLs")
    void testGetCRLURLs() {
        SimpleCrlCache crlCache = new SimpleCrlCache();
        String crlDistributionPoint1 = "http://crl.idporten.no/c1";
        String crlDistributionPoint2 = "http://crl.idporten.no/c2";

        crlCache.set(crlDistributionPoint1, mock(X509CRL.class));
        crlCache.set(crlDistributionPoint2, mock(X509CRL.class));

        assertAll(
                () -> assertEquals(2, crlCache.getUrls().size()),
                () -> assertTrue(crlCache.getUrls().contains(crlDistributionPoint1)),
                () -> assertTrue(crlCache.getUrls().contains(crlDistributionPoint2))
                );
    }

    @Test
    @DisplayName("then a null CRL will be removed from the cache")
    void testRemoveNullCRLFromCache() {
        SimpleCrlCache crlCache = new SimpleCrlCache();
        String crlDistributionPoint = "http://crl.idporten.no/c1";

        crlCache.set(crlDistributionPoint, mock(X509CRL.class));
        assertNotNull(crlCache.get(crlDistributionPoint));

        crlCache.set(crlDistributionPoint, null);
        assertNull(crlCache.get(crlDistributionPoint));
    }

    @Test
    @DisplayName("then a CRL can be added to and fetched from the cache")
    void testSetGetCRLsWithCache() {
        SimpleCrlCache crlCache = new SimpleCrlCache();
        X509CRL crl = mock(X509CRL.class);
        String crlDistributionPoint = "http://crl.idporten.no/c1";

        crlCache.set(crlDistributionPoint, crl);
        assertEquals(crl, crlCache.get(crlDistributionPoint));
    }

}
