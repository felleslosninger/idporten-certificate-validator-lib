package no.idporten.validator.certificate.rule;


import no.idporten.validator.certificate.Validator;
import no.idporten.validator.certificate.ValidatorBuilder;
import no.idporten.validator.certificate.api.FailedValidationException;
import no.idporten.validator.certificate.api.Report;
import no.idporten.validator.certificate.util.SimpleReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("When validating certificate policies")
public class PolicyRuleTest {

    @DisplayName("Then a certificate matching at least one accepted policy should validate")
    @Test
    public void testAtLeastOneMatchingPolicy() throws Exception {
        Validator validator = ValidatorBuilder.newInstance()
                .addRule(new PolicyRule("2.16.578.1.29.913.210.1.0", "2.16.578.1.29.913.210.1.1", "2.16.578.1.29.913.210.1.2"))
                .build();
        Report report = SimpleReport.newInstance();
        validator.validate(getClass().getResourceAsStream("/digdir_seid2.cer"), report);
        assertAll(
                () -> assertEquals(1, report.get(PolicyRule.POLICY).size()),
                () -> assertTrue(report.get(PolicyRule.POLICY).contains("2.16.578.1.29.913.210.1.0"))
        );
    }

    @DisplayName("Then a certificate wildcard-matching at least one accepted policy should validate")
    @Test
    public void testWildcardPolicyPolicy() throws Exception {
        Validator validator = ValidatorBuilder.newInstance()
                .addRule(new PolicyRule("2.16.578.1.29.913.210.*"))
                .build();
        Report report = SimpleReport.newInstance();
        validator.validate(getClass().getResourceAsStream("/digdir_seid2.cer"), report);
        assertAll(
                () -> assertEquals(1, report.get(PolicyRule.POLICY).size()),
                () -> assertTrue(report.get(PolicyRule.POLICY).contains("2.16.578.1.29.913.210.1.0"))
        );
    }

    @DisplayName("Then a certificate not matching any accepted policy should not validate")
    @Test
    public void testNoMatchingPolicy() throws Exception {
        Validator validator = ValidatorBuilder.newInstance()
                .addRule(new PolicyRule("2.16.578.1.29.913.211.banan"))
                .build();
        FailedValidationException e = assertThrows(FailedValidationException.class, () -> validator.validate(getClass().getResourceAsStream("/digdir_seid2.cer")));
        assertEquals("No accepted policies found in certificate.", e.getMessage());
    }

}
