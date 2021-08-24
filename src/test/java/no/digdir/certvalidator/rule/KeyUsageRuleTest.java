package no.digdir.certvalidator.rule;

import no.digdir.certvalidator.Validator;
import no.digdir.certvalidator.api.FailedValidationException;
import no.digdir.certvalidator.util.KeyUsage;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author erlend
 */
@DisplayName("When key usage rules")
public class KeyUsageRuleTest {

    @Test
    @DisplayName("validation should pass if keyusage bits in certificate matches the rule")
    public void simpleValid() throws Exception {
        new Validator(
                new KeyUsageRule(KeyUsage.NON_REPUDIATION))
                .validate(getClass().getResourceAsStream("/virksert-test-difi.cer"));
    }

    @Test
    @DisplayName("validation should fail if certificate has keyusage bits not matched in the rule")
    public void simpleFailed() throws Exception {
        assertThrows(FailedValidationException.class,
                () -> new Validator(new KeyUsageRule())
                .validate(getClass().getResourceAsStream("/virksert-test-difi.cer")));
    }

    @Test
    @DisplayName("validation should pass if keyusage bits in certificate matches the rule")
    public void simplePeppol() throws Exception {
        new Validator(new KeyUsageRule(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT,
                KeyUsage.DATA_ENCIPHERMENT, KeyUsage.KEY_AGREEMENT))
                .validate(getClass().getResourceAsStream("/peppol-prod-smp-difi.cer"));
    }
}