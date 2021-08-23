package no.digdir.certvalidator.rule;

import no.digdir.certvalidator.Validator;
import no.digdir.certvalidator.testutil.X509TestGenerator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.ZoneId;
import java.time.ZonedDateTime;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("When validation expiration soon rules")
public class ExpirationSoonRuleTest extends X509TestGenerator {

    @Test
    @DisplayName("validation should pass if expiration is more than x days after today or else fail")
    public void simple() throws Exception {
        Validator validatorHelper = new Validator(new ExpirationSoonRule(5 * 24 * 60 * 60 * 1000));

        ZonedDateTime now = ZonedDateTime.now(ZoneId.systemDefault());
        assertTrue(validatorHelper.isValid(createX509Certificate(toDate(now.plusDays(1)), toDate(now.plusDays(10)))));
        assertTrue(validatorHelper.isValid(createX509Certificate(toDate(now.plusDays(1)), toDate(now.plusDays(6)))));
        assertTrue(validatorHelper.isValid(createX509Certificate(toDate(now.plusDays(1)), toDate(now.plusDays(5).plusMinutes(1)))));
        assertFalse(validatorHelper.isValid(createX509Certificate(toDate(now.plusDays(1)), toDate(now.plusDays(5).minusMinutes(1)))));
        assertFalse(validatorHelper.isValid(createX509Certificate(toDate(now.plusDays(1)), toDate(now.plusDays(4)))));
    }

}
