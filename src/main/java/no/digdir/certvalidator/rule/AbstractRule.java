package no.digdir.certvalidator.rule;

import no.digdir.certvalidator.api.CertificateValidationException;
import no.digdir.certvalidator.api.Report;
import no.digdir.certvalidator.api.ValidatorRule;
import no.digdir.certvalidator.util.DummyReport;

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
