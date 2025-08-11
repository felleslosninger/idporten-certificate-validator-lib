package no.idporten.validator.certificate.rule;


import no.idporten.validator.certificate.Validator;
import no.idporten.validator.certificate.util.SimpleCertificateBucket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author erlend
 */
@DisplayName("When white list rules")
public class WhitelistRuleTest {

    @Test
    @DisplayName("Certificate should pass validation if on white list and fail validation if not on whitelist")
    public void simple() throws Exception {
        X509Certificate certificate;

        try (InputStream inputStream = getClass().getResourceAsStream("/selfsigned.cer")) {
            certificate = Validator.getCertificate(inputStream);
        }

        assertTrue(new Validator(new WhitelistRule(SimpleCertificateBucket.with(certificate))).isValid(certificate));
        assertFalse(new Validator(new WhitelistRule(SimpleCertificateBucket.with())).isValid(certificate));
    }

}
