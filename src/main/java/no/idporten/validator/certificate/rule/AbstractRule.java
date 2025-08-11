package no.idporten.validator.certificate.rule;

import no.idporten.validator.certificate.api.CertificateValidationException;
import no.idporten.validator.certificate.api.Report;
import no.idporten.validator.certificate.api.ValidatorRule;
import no.idporten.validator.certificate.util.DummyReport;

import java.security.cert.X509Certificate;

/**
 * @author erlend
 */
public abstract class AbstractRule implements ValidatorRule {

    @Override
    public Report validate(X509Certificate certificate, Report report) throws CertificateValidationException {
        validate(certificate);
        
        return report;
    }

    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        validate(certificate, DummyReport.INSTANCE);
    }
}
