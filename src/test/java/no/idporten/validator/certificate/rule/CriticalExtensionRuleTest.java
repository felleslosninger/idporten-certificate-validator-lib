package no.idporten.validator.certificate.rule;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("When validating critial extensions recognized rules")
public class CriticalExtensionRuleTest {

    @Test
    @DisplayName("validate that rule can be constructed (no implementation)")
    public void simpleConstructor() {
        new CriticalExtensionRule();
    }

}
