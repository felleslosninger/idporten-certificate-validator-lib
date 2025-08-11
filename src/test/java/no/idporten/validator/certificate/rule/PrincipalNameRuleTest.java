package no.idporten.validator.certificate.rule;

import no.idporten.validator.certificate.ValidatorBuilder;
import no.idporten.validator.certificate.api.CertificateValidationException;
import no.idporten.validator.certificate.api.FailedValidationException;
import no.idporten.validator.certificate.util.SimplePrincipalNameProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("When invoking PrincipalNameRule on a certificate with subject C=NO and issuer C=DK")
public class PrincipalNameRuleTest {

    @Test
    @DisplayName("validation should pass if NO is demanded as principal name")
    public void onlyNoAllowed() throws Exception {
        ValidatorBuilder.newInstance()
                .addRule(new PrincipalNameRule("C", new SimplePrincipalNameProvider("NO")))
                .build()
                .validate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));
    }

    @Test
    @DisplayName("validation should fail if DK is demanded as principal name")
    public void onlyDkAllowedFail()  {
        FailedValidationException exception = assertThrows(FailedValidationException.class,
                () -> ValidatorBuilder.newInstance()
                        .addRule(new PrincipalNameRule("C", new SimplePrincipalNameProvider("DK")))
                        .build()
                        .validate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
        assertEquals("Validation of subject principal(C) failed.", exception.getMessage());
    }

    @Test
    @DisplayName("validation should pass if DK is demanded as principal name of issuer")
    public void onlyDkAllowedOK() throws CertificateValidationException {
        ValidatorBuilder.newInstance()
                .addRule(new PrincipalNameRule("C", new SimplePrincipalNameProvider("DK"), PrincipalNameRule.Principal.ISSUER))
                .build()
                .validate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));
    }

    @Test
    @DisplayName("validation should fail if format of wrapped principal doesn't match (in this case NO instead of NORWAY)")
    public void fullName() {
        FailedValidationException exception = assertThrows(FailedValidationException.class,
                () -> ValidatorBuilder.newInstance()
                        .addRule(new PrincipalNameRule((value) -> value.contains("NORWAY"), PrincipalNameRule.Principal.SUBJECT))
                        .build()
                        .validate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
        assertEquals("Validation of subject principal(null) failed.", exception.getMessage());
    }

}
