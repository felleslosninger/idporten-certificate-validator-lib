package no.digdir.certvalidator.rule;


import no.digdir.certvalidator.api.CertificateBucket;
import no.digdir.certvalidator.api.CertificateValidationException;
import no.digdir.certvalidator.api.FailedValidationException;

import java.security.cert.X509Certificate;

/**
 * @author erlend
 */
public class BlacklistRule extends AbstractRule {

    private final CertificateBucket certificates;

    public BlacklistRule(CertificateBucket certificates) {
        this.certificates = certificates;
    }

    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        for (X509Certificate cert : certificates) {
            if (cert.equals(certificate))
                throw new FailedValidationException("Certificate is blacklisted.");
        }
    }
}
