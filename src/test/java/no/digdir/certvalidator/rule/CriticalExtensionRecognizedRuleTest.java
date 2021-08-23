package no.digdir.certvalidator.rule;

import no.digdir.certvalidator.Validator;
import no.digdir.certvalidator.ValidatorBuilder;
import no.digdir.certvalidator.api.FailedValidationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("When validating critial extensions recognized rules")
public class CriticalExtensionRecognizedRuleTest {

    @DisplayName("Should fail if certificate has oids that are not recognized")
    @Test
    public void certificateHasOidsNotRecognized() throws Exception {
        Validator validator = new Validator(new CriticalExtensionRecognizedRule("12.0"));
        FailedValidationException failedValidationException = assertThrows(FailedValidationException.class,
                () -> validator.validate(getClass().getResourceAsStream("/difi-move-test.cer")));
        assertEquals("X509 certificate 174730041 specifies a critical extension 2.5.29.15 which is not recognized", failedValidationException.getMessage());
    }

    @DisplayName("Should not fail if certificate has oids that are not recognized")
    @Test
    public void triggerNoExceptionsWhenCertHasNoCriticalOids() throws Exception {
        ValidatorBuilder.newInstance()
                .addRule(CriticalExtensionRule.recognizes("12.0"))
                .build()
                .validate(getClass().getResourceAsStream("/nooids.cer"));
    }
}
