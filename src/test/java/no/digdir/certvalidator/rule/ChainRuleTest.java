package no.digdir.certvalidator.rule;


import no.digdir.certvalidator.Validator;
import no.digdir.certvalidator.ValidatorBuilder;
import no.digdir.certvalidator.api.CertificateBucket;
import no.digdir.certvalidator.api.FailedValidationException;
import no.digdir.certvalidator.util.SimpleCertificateBucket;
import no.digdir.certvalidator.util.SimpleReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("When validating chain of certificates")
public class ChainRuleTest {

    @DisplayName("Simple, valid certificate chain should validate ok")
    @Test
    public void simple() throws Exception {
        X509Certificate intermediateCertificate = Validator.getCertificate(getClass().getResourceAsStream("/commfides_intermediate_g3_test.cer"));
        X509Certificate rootCertificate = Validator.getCertificate(getClass().getResourceAsStream("/commfides_root_g3_test.cer"));
        CertificateBucket rootCertificates = new SimpleCertificateBucket(rootCertificate);
        CertificateBucket intermediateCertificates = new SimpleCertificateBucket(intermediateCertificate);

        Validator validator = ValidatorBuilder.newInstance()
                .addRule(new ChainRule(rootCertificates, intermediateCertificates))
                .build();

        validator.validate(getClass().getResourceAsStream("/digdir_seid2.cer"));
        validator.validate(getClass().getResourceAsStream("/commfides_intermediate_g3_test.cer"));
        validator.validate(getClass().getResourceAsStream("/commfides_root_g3_test.cer"), SimpleReport.newInstance());
    }

    @DisplayName("If root certificates are missing, should fail with message")
    @Test
    public void missingRootCertificate() throws Exception {
            X509Certificate intermediateCertificate = Validator.getCertificate(getClass().getResourceAsStream("/Buypass_Class_3_Test4_CA_G2_ST_Business_Buypass_Class_3_Test4_Root_CA_G2_ST_intermediary.cer"));
            CertificateBucket intermediateCertificates = new SimpleCertificateBucket(intermediateCertificate);


            Validator validator = ValidatorBuilder.newInstance()
                    .addRule(new ChainRule(new SimpleCertificateBucket(), intermediateCertificates))
                    .build();

        FailedValidationException failedValidationException = assertThrows(FailedValidationException.class,
                () -> validator.validate(getClass().getResourceAsStream("/buypass-psd2.cer")));
        assertEquals("the trustAnchors parameter must be non-empty", failedValidationException.getMessage());

    }

}
