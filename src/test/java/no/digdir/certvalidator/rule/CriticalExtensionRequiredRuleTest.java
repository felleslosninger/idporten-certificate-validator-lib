package no.digdir.certvalidator.rule;


import no.digdir.certvalidator.Validator;
import no.digdir.certvalidator.ValidatorBuilder;
import no.digdir.certvalidator.api.FailedValidationException;
import no.digdir.certvalidator.testutil.X509ExtensionCustom;
import no.digdir.certvalidator.testutil.X509TestGenerator;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("When critial extensions required rules")
public class CriticalExtensionRequiredRuleTest extends X509TestGenerator {

    @Test
    @DisplayName("should fail validation if certificate does not contain critical extensions")
    public void shouldValidateCertWithOutAnyCriticalExtentions() throws Exception {
        CriticalExtensionRequiredRule validator = new CriticalExtensionRequiredRule("2");
        X509Certificate cert = createX509Certificate();
        FailedValidationException exception = assertThrows(FailedValidationException.class,
                () -> validator.validate(cert));
        assertEquals("Certificate doesn't contain critical OIDs.", exception.getMessage());
    }


    @Test
    @DisplayName("should pass validation if certificate contains critical extensions")
    public void shouldValidateCertWithApprovedCriticalExtentions() throws Exception {
        CriticalExtensionRequiredRule validator = CriticalExtensionRule.requires("2.10.2");
        X509Certificate cert = createX509Certificate(new X509ExtensionCustom() {
            public void setup(X509v3CertificateBuilder v3CertGen) throws CertIOException {
                v3CertGen.addExtension(new ASN1ObjectIdentifier("2.10.2"), true, new byte[3]);
            }

        });
        validator.validate(cert);
    }

    @Test
    @DisplayName("should fail validation if certificate contains critical extensions not approved by validator")
    public void shouldInvalidateCertWithACriticalExtentionsThatIsNotApproved() throws Exception {
        String approvedExtentionList = "2.10.2";
        CriticalExtensionRequiredRule validator = CriticalExtensionRule.requires(approvedExtentionList);
        X509Certificate cert = createX509Certificate(v3CertGen -> {
            String notApprovedExtention = "2.10.6";
            v3CertGen.addExtension(new ASN1ObjectIdentifier(notApprovedExtention), true, new byte[3]);
        });
        FailedValidationException exception = assertThrows(FailedValidationException.class,
                () -> validator.validate(cert));
        assertEquals("Certificate doesn't contain critical OID '2.10.2'.", exception.getMessage());
    }

    @Test
    @DisplayName("should fail validation if certificate does not contains critical extensions demanded by validator")
    public void triggerExceptionWhenCertHasNoCriticalOids() throws Exception {
        Validator validator = ValidatorBuilder.newInstance()
                .addRule(CriticalExtensionRule.requires("12.0"))
                .build();
        FailedValidationException exception = assertThrows(FailedValidationException.class,
                () -> validator.validate(getClass().getResourceAsStream("/nooids.cer")));
        assertEquals("Certificate doesn't contain critical OIDs.", exception.getMessage());
    }
}
