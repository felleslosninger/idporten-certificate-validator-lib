package no.digdir.certvalidator.rule;


import no.digdir.certvalidator.Validator;
import no.digdir.certvalidator.api.CertificateValidationException;
import no.digdir.certvalidator.api.FailedValidationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("When signing rules")
public class SigningRuleTest {

    @Test
    @DisplayName("should pass validation if rule is publicly signed and certificate is publicly signed")
    public void publiclySignedExpectedWithPubliclySigned() throws Exception {
        SigningRule.PublicSignedOnly()
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }

    @Test
    @DisplayName("should fail validation if rule is self signed and certificate is publicly signed")
    public void selfSignedExpectedWithPubliclySigned() {
        FailedValidationException failedValidationException = assertThrows(FailedValidationException.class,
                () -> SigningRule.SelfSignedOnly()
                        .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"))));
        assertEquals("Certificate should be self-signed.", failedValidationException.getMessage());
    }

    @Test
    @DisplayName("should fail validation if rule is publicly signed and certificate is self signed")
    public void publiclySignedExpectedWithSelfSigned()  {
        FailedValidationException failedValidationException = assertThrows(FailedValidationException.class,
                () -> SigningRule.PublicSignedOnly()
                        .validate(Validator.getCertificate(getClass().getResourceAsStream("/selfsigned.cer"))));
        assertEquals("Certificate should be publicly signed.", failedValidationException.getMessage());
    }

    @Test
    @DisplayName("should pass validation if rule is self signed and certificate is self signed")
    public void selfSignedExpectedWithSelfSigned() throws Exception {
        SigningRule.SelfSignedOnly()
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/selfsigned.cer")));
    }

    @Test
    @DisplayName("should throw CertificateValidationException if trying to validate null as certificate")
    public void triggerException() throws Exception {
        CertificateValidationException certificateValidationException = assertThrows(CertificateValidationException.class,
                () -> SigningRule.PublicSignedOnly().validate(null));
        assertEquals("Certificate is null.", certificateValidationException.getMessage());
    }

}
