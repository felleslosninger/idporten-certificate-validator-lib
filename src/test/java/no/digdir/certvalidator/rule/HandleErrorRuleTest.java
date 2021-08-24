package no.digdir.certvalidator.rule;


import no.digdir.certvalidator.Validator;
import no.digdir.certvalidator.api.CertificateValidationException;
import no.digdir.certvalidator.api.FailedValidationException;
import no.digdir.certvalidator.api.Report;
import no.digdir.certvalidator.api.ValidatorRule;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("When wrapping other rules in HandleErrorRule")
public class HandleErrorRuleTest {

    @Test
    @DisplayName("validation should pass if wrapped rule validates ok")
    public void simpleOk() throws CertificateValidationException {
        new Validator(new HandleErrorRule(new DummyRule()))
                .validate(getClass().getResourceAsStream("/selfsigned.cer"));
    }

    @Test
    @DisplayName("validation should fail with message from wrapped rule if wrapped rule fails")
    public void simpleFailed()  {
        FailedValidationException exception = assertThrows(FailedValidationException.class,
                () -> new Validator(new HandleErrorRule(new DummyRule("Trigger me!")))
                        .validate(getClass().getResourceAsStream("/selfsigned.cer")));
        assertEquals("Trigger me!", exception.getMessage());
    }

    @Test
    @DisplayName("validation should pass even if wrapped rule fails if no errorhandler is configured in HandleErrorRule")
    public void simpleUnknown() throws CertificateValidationException {
        new Validator(new HandleErrorRule(new ValidatorRule() {
            @Override
            public void validate(X509Certificate certificate) throws CertificateValidationException {
                throw new CertificateValidationException("Unable to load something...");
            }

            @Override
            public Report validate(X509Certificate certificate, Report report) throws CertificateValidationException {
                throw new CertificateValidationException("Unable to load something...2");
            }
        }))
                .validate(getClass().getResourceAsStream("/selfsigned.cer"));
    }

    @Test
    @DisplayName("validation should fail if wrapped rule fails, and errorhandler in HandleErrorRule should be invoked, " +
            "here CertificateValidationException is transformed to FailedValidationException with the same message")
    public void triggerException()  {
        Validator validator = new Validator(new HandleErrorRule(e -> {
            throw new FailedValidationException(e.getMessage(), e);
        }, new ValidatorRule() {
            @Override
            public void validate(X509Certificate certificate) throws CertificateValidationException {
                throw new CertificateValidationException("Test");
            }

            @Override
            public Report validate(X509Certificate certificate, Report report) throws CertificateValidationException {
                throw new CertificateValidationException("Test2");
            }
        }));
        FailedValidationException failedValidationException = assertThrows(FailedValidationException.class,
                () -> validator.validate(getClass().getResourceAsStream("/selfsigned.cer")));
        assertEquals("Test", failedValidationException.getMessage());
    }
}
