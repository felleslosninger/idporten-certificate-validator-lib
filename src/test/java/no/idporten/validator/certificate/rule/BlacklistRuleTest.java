package no.idporten.validator.certificate.rule;


import no.idporten.validator.certificate.Validator;
import no.idporten.validator.certificate.api.FailedValidationException;
import no.idporten.validator.certificate.util.SimpleCertificateBucket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author erlend
 */
@DisplayName("When validating a blacklist rule")
public class BlacklistRuleTest {

    @DisplayName("Simple validation should return message if failing")
    @Test()
    public void simple() throws Exception {
        X509Certificate certificate;

        try (InputStream inputStream = getClass().getResourceAsStream("/selfsigned.cer")) {
            certificate = Validator.getCertificate(inputStream);
        }

        Validator blacklistWithCertificate = new Validator(new BlacklistRule(SimpleCertificateBucket.with(certificate)));
        assertFalse(blacklistWithCertificate.isValid(certificate));
        FailedValidationException failedValidationException = assertThrows(FailedValidationException.class,
                () -> blacklistWithCertificate.validate(certificate));
        assertEquals("Certificate is blacklisted.", failedValidationException.getMessage());
        assertTrue(new Validator(new BlacklistRule(SimpleCertificateBucket.with())).isValid(certificate));
    }

}
