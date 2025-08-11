package no.idporten.validator.certificate.structure;

import no.idporten.validator.certificate.api.CertificateValidationException;
import no.idporten.validator.certificate.api.FailedValidationException;
import no.idporten.validator.certificate.api.Report;
import no.idporten.validator.certificate.api.ValidatorRule;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Allows combining instances of validators using a limited set of logic.
 */
public class OrJunction extends AbstractJunction {

    public OrJunction(ValidatorRule... validatorRules) {
        super(validatorRules);
    }

    public OrJunction(List<ValidatorRule> validatorRules) {
        super(validatorRules);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Report validate(X509Certificate certificate, Report report) throws CertificateValidationException {
        List<CertificateValidationException> exceptions = new ArrayList<>();

        for (ValidatorRule validatorRule : validatorRules) {
            try {
                return validatorRule.validate(certificate, report.copy());
            } catch (CertificateValidationException e) {
                exceptions.add(e);
            }
        }

        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("Or-junction failed with results:");
        for (Exception e : exceptions)
            stringBuilder.append("\n* ").append(e.getMessage());

        throw new FailedValidationException(stringBuilder.toString());
    }
}
