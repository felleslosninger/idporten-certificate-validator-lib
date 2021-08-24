package no.digdir.certvalidator.rule;

import no.digdir.certvalidator.Validator;
import no.digdir.certvalidator.ValidatorBuilder;
import no.digdir.certvalidator.api.CertificateValidationException;
import no.digdir.certvalidator.api.CrlCache;
import no.digdir.certvalidator.api.FailedValidationException;
import no.digdir.certvalidator.util.SimpleCachingCrlFetcher;
import no.digdir.certvalidator.util.SimpleCrlCache;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@DisplayName("When validating CRL-rules")
public class CRLRuleTest {

    private static String CRL_URL = "http://pilotonsitecrl.verisign.com/DigitaliseringsstyrelsenPilotOpenPEPPOLACCESSPOINTCA/LatestCRL.crl";

    @Test
    @DisplayName("validate simple rule with mocked CRLFetcher")
    public void simple() throws Exception {
        SimpleCachingCrlFetcher crlFetcher = Mockito.mock(SimpleCachingCrlFetcher.class);
        X509CRL x509CRL = Mockito.mock(X509CRL.class);
        when(crlFetcher.get(CRL_URL)).thenReturn(x509CRL);
        ValidatorBuilder.newInstance()
                .addRule(new CRLRule(crlFetcher))
                .build()
                .validate((getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }


    @Test
    @DisplayName("parsing should throw CertificateValidationException when no set with urls is available for CRL (actually wrapped NullpointerException)")
    public void noUrlsSet() throws Exception {
        X509Certificate certificate = Validator.getCertificate(getClass().getResourceAsStream("/nooids.cer"));
        CertificateValidationException certificateValidationException = assertThrows(CertificateValidationException.class,
                () -> CRLRule.getCrlDistributionPoints(certificate));
        assertNull(certificateValidationException.getMessage());
    }

    @Test
    @DisplayName("validation should pass when no urls in set")
    public void noUrlsInSet() throws Exception {
        X509Certificate certificate = Mockito.mock(X509Certificate.class);
        Mockito.doReturn(Collections.emptySet()).when(certificate).getNonCriticalExtensionOIDs();

        assertEquals(CRLRule.getCrlDistributionPoints(certificate).size(), 0);
    }

    @Test
    @DisplayName("validation should fail when certificate is listed as revoked")
    public void revoked() throws Exception {
        X509Certificate certificate = Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));

        X509CRL x509CRL = Mockito.mock(X509CRL.class);
        Mockito.doReturn(true).when(x509CRL).isRevoked(certificate);

        CrlCache crlCache = new SimpleCrlCache();
        crlCache.set("http://pilotonsitecrl.verisign.com/DigitaliseringsstyrelsenPilotOpenPEPPOLACCESSPOINTCA/LatestCRL.crl", x509CRL);

        CRLRule rule = new CRLRule(crlCache);
        FailedValidationException failedValidationException = assertThrows(FailedValidationException.class,
                () -> rule.validate(certificate));
        assertEquals("Certificate is revoked.", failedValidationException.getMessage());
    }

    @Test
    @DisplayName("Validation should pass when CRLRule doesn't list url")
    public void crlIsNull() throws Exception {
        X509Certificate certificate = Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));

        CRLRule rule = new CRLRule(url -> null);
        rule.validate(certificate);
    }
}
