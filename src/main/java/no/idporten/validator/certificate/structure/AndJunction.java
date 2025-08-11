package no.idporten.validator.certificate.structure;


import no.idporten.validator.certificate.api.CertificateValidationException;
import no.idporten.validator.certificate.api.Report;
import no.idporten.validator.certificate.api.ValidatorRule;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Allows combining instances of validators using a limited set of logic.
 */
public class AndJunction extends AbstractJunction {

    public AndJunction(ValidatorRule... validatorRules) {
        super(validatorRules);
    }

    public AndJunction(List<ValidatorRule> validatorRules) {
        super(validatorRules);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Report validate(X509Certificate certificate, Report report) throws CertificateValidationException {
        for (ValidatorRule validatorRule : validatorRules)
            report = validatorRule.validate(certificate, report.copy());

        return report;
    }
}
