package no.idporten.validator.certificate.rule;

import no.idporten.validator.certificate.api.CertificateValidationException;
import no.idporten.validator.certificate.api.FailedValidationException;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.TimeZone;

/**
 * Validation making sure certificate doesn't expire in n milliseconds.
 */
public class ExpirationSoonRule extends AbstractRule {

    private long millis;

    public ExpirationSoonRule(long millis) {
        this.millis = millis;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        if (certificate.getNotAfter().getTime() < (System.currentTimeMillis() + millis))
            throw new FailedValidationException(String.format("Certificate expires in less than %s milliseconds.", millis));
    }
}
