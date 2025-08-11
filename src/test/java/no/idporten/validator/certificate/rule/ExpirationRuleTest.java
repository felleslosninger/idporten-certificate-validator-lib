package no.idporten.validator.certificate.rule;


import no.idporten.validator.certificate.api.CertificateValidationException;
import no.idporten.validator.certificate.api.FailedValidationException;
import no.idporten.validator.certificate.testutil.X509TestGenerator;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("When validation expiration rules")
public class ExpirationRuleTest extends X509TestGenerator {

    @Test
    @DisplayName("validation should pass when certificate is valid")
    public void shouldValidateAValidCertificate() throws CertificateValidationException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, CertIOException, OperatorCreationException {
        ExpirationRule validator = new ExpirationRule();

        X509Certificate cert = createX509Certificate(toDate(ZonedDateTime.now(ZoneId.systemDefault()).minusDays(10)), toDate(ZonedDateTime.now(ZoneId.systemDefault()).plusDays(10)));

        validator.validate(cert);
    }

    @Test
    @DisplayName("validation should fail when certificate is not yet valid")
    public void shouldInvalidateAExpiredCertificate() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, CertIOException, OperatorCreationException {
        ExpirationRule validator = new ExpirationRule();

        X509Certificate cert = createX509Certificate(toDate(ZonedDateTime.now(ZoneId.systemDefault()).minusDays(10)), toDate(ZonedDateTime.now(ZoneId.systemDefault()).minusDays(2)));
        FailedValidationException exception = assertThrows(FailedValidationException.class,
                () -> validator.validate(cert));
        assertEquals("Certificate does not have a valid expiration date.", exception.getMessage());
    }

    @Test
    @DisplayName("validation should fail when expiration date is passed ")
    public void shouldInvalidateANotNotbeforeCertificate() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, CertIOException, OperatorCreationException {
        ExpirationRule validator = new ExpirationRule();

        X509Certificate cert = createX509Certificate(toDate(ZonedDateTime.now(ZoneId.systemDefault()).plusDays(10)), toDate(ZonedDateTime.now(ZoneId.systemDefault()).plusDays(20)));

        FailedValidationException exception = assertThrows(FailedValidationException.class,
                () -> validator.validate(cert));
        assertEquals("Certificate does not have a valid expiration date.", exception.getMessage());
    }
}
