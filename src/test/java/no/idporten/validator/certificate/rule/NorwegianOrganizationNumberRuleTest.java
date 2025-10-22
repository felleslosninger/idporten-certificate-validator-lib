package no.idporten.validator.certificate.rule;

import no.idporten.validator.certificate.Validator;
import no.idporten.validator.certificate.ValidatorBuilder;
import no.idporten.validator.certificate.api.CertificateValidationException;
import no.idporten.validator.certificate.api.FailedValidationException;
import no.idporten.validator.certificate.testutil.X509TestGenerator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("When validating and parsing norwegian organization numbers")
class NorwegianOrganizationNumberRuleTest {

    private final X509TestGenerator x509TestGenerator = new X509TestGenerator();

    @Test
    @DisplayName("orgnumber should be extracted correctly when in field serialNumber")
    public void shouldExtractOrgnumberFromCertBasedOnSerialnumber() throws Exception {
        final String ORGNR = "123456789";
        X509Certificate cert = x509TestGenerator.createX509Certificate("CN=name, OU=None, O=None, L=None, C=None, serialNumber=" + ORGNR);

        new NorwegianOrganizationNumberRule(value -> {
            assertEquals(ORGNR, value);
            return true;
        }).validate(cert);
    }

    @Test
    @DisplayName("orgnumber should be extracted correctly when in field 2.5.4.97")
    public void shouldExtractOrgnumberFromCertBasedOnPSD2() throws Exception {
        final String ORGNR = "123456789";
        X509Certificate cert = x509TestGenerator.createX509Certificate("CN=name, OU=None, O=None, L=None, C=None, 2.5.4.97=PSDNO-FSA-" + ORGNR);

        new NorwegianOrganizationNumberRule(value -> {
            assertEquals(ORGNR, value);
            return true;
        }).validate(cert);
    }

    @Test
    @DisplayName("validation should fail if orgnr is on invalid format")
    public void invalidOrgnumberFromCertBasedOnSerialnumber() throws Exception {
        final String ORGNR = "123 456 789";
        X509Certificate cert = x509TestGenerator.createX509Certificate("CN=name, OU=None, O=None, L=None, C=None, serialNumber=" + ORGNR);
        FailedValidationException failedValidationException = assertThrows(FailedValidationException.class,
                () -> new NorwegianOrganizationNumberRule(value -> true).validate(cert));
        assertEquals("Organization number not detected.", failedValidationException.getMessage());
    }

    @Test
    @DisplayName("orgnumber should be extracted correctly when in field O=organisasjon")
    public void shouldExtractOrgnumberFromCertBasedOnOrgNumberInOrganization() throws Exception {
        final String ORGNR = "123456789";
        X509Certificate cert = x509TestGenerator.createX509Certificate("CN=name, OU=None, O=organisasjon - " + ORGNR + ", L=None, C=None");

        NorwegianOrganizationNumberRule.NorwegianOrganization orgnr = NorwegianOrganizationNumberRule.extractNumber(cert);
        assertEquals(ORGNR, orgnr.getNumber());
        assertEquals("organisasjon - 123456789", orgnr.getName());

    }

    @Test
    @DisplayName("orgnumber should be extracted correctly when from Commfides certificate")
    public void shouldExtractOrgnumberFromCommfidesCert() throws Exception {
        final String ORGNR = "399573952";
        X509Certificate cert = x509TestGenerator.createX509Certificate("C=NO,ST=AKERSHUS,L=FORNEBUVEIEN 1\\, 1366 LYSAKER,O=RF Commfides,SERIALNUMBER=399573952,CN=RF Commfides");

        new NorwegianOrganizationNumberRule(value -> {
            assertEquals(ORGNR, value);
            return true;
        }).validate(cert);
    }

    @Test
    @DisplayName("orgnumber from PSD2 certificate should be extracted correctly when in field 2.5.4.97")
    public void shouldExtractOrgnumberFromPSD2Cert() throws Exception {
        final String ORGNR = "991825827";
        X509Certificate cert = x509TestGenerator.createX509Certificate("2.5.4.97=PSDNO-FSA-991825827,CN=DIGITALISERINGSDIREKTORATET,OU=FDF Test PSD2 QC,O=DIGITALISERINGSDIREKTORATET,C=NO");

        new NorwegianOrganizationNumberRule(value -> {
            assertEquals(ORGNR, value);
            return true;
        }).validate(cert);
    }

    @Test
    @DisplayName("validation should fail when attribute with organization number is not detected")
    public void attributesNotFound() throws Exception {
        X509Certificate cert = x509TestGenerator.createX509Certificate("CN=name");

        FailedValidationException exception = assertThrows(FailedValidationException.class,
                () -> new NorwegianOrganizationNumberRule().validate(cert));
        assertEquals("Organization number not detected.", exception.getMessage());
    }

    @Test
    @DisplayName("validation should fail when name rule of wrapped PrincipalNameProvider fails")
    public void notAcceptedOrgnumberFromCertBasedOnSerialnumber() throws Exception {
        final String ORGNR = "123456789";
        X509Certificate cert = x509TestGenerator.createX509Certificate("CN=name, OU=None, O=None, L=None, C=None, serialNumber=" + ORGNR);

        FailedValidationException exception = assertThrows(FailedValidationException.class,
                () -> new NorwegianOrganizationNumberRule(
                        //accept no organization names
                        value -> false)
                        .validate(cert)
        );
        assertEquals("Organization number not detected.", exception.getMessage());
    }

    @Test
    @DisplayName("validation fails with CertificateValidationException with no message when certificate is empty")
    public void triggerExceptionInExtractNumber() {
        CertificateValidationException certificateValidationException = assertThrows(CertificateValidationException.class,
                () -> NorwegianOrganizationNumberRule.extractNumber(null));
        assertEquals("Certificate is null.", certificateValidationException.getMessage());
    }

    @Test
    @DisplayName("validation should pass with valid certificate issued by Commfides")
    public void testingMoveCertificate() throws Exception {
        X509Certificate certificate = Validator.getCertificate(getClass().getResourceAsStream("/commfides_intermediate_g3_test.cer"));

        Validator validator = ValidatorBuilder.newInstance()
                .addRule(new ExpirationRule())
                .addRule(SigningRule.PublicSignedOnly())
                .addRule(CriticalExtensionRule.recognizes("2.5.29.15", "2.5.29.19"))
                .addRule(CriticalExtensionRule.requires("2.5.29.15"))
                .addRule(new NorwegianOrganizationNumberRule(s -> {
                    // Accept all organization numbers.
                    return true;
                }))
                .build();

        validator.validate(certificate);
    }
}