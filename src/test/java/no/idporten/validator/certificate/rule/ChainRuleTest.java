package no.idporten.validator.certificate.rule;


import no.idporten.validator.certificate.Validator;
import no.idporten.validator.certificate.ValidatorBuilder;
import no.idporten.validator.certificate.api.CertificateBucket;
import no.idporten.validator.certificate.api.FailedValidationException;
import no.idporten.validator.certificate.testutil.TestDataConstants;
import no.idporten.validator.certificate.testutil.TestDataUtils;
import no.idporten.validator.certificate.util.SimpleCertificateBucket;
import no.idporten.validator.certificate.util.SimpleReport;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static no.idporten.validator.certificate.testutil.TestDataUtils.generateCertificate;
import static no.idporten.validator.certificate.testutil.TestDataUtils.generateRSAKeyPair;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("When validating chain of certificates")
public class ChainRuleTest {
    static {
        // required to generate certificates
        Security.addProvider(new BouncyCastleProvider());
    }

    @DisplayName("Simple, valid certificate chain should validate ok")
    @Test
    public void simple() throws Exception {

        // given we have a valid key set
        final var halfYear = Duration.ofDays(180);
        final var validStart = Date.from(Instant.now().minus(halfYear));
        final var validEnd = Date.from(Instant.now().plus(halfYear));
        final var caKeys = generateRSAKeyPair();
        final var intermediateKeys = generateRSAKeyPair();
        final var signatureKeys = generateRSAKeyPair();

        final X509Certificate rootCertificate = generateCertificate(caKeys.getPublic(), caKeys.getPrivate(), "CN=Sertifikatcompagniet CA", "CN=Sertifikatcompagniet CA", validStart, validEnd, true);
        final X509Certificate intermediateCertificate = generateCertificate(intermediateKeys.getPublic(), caKeys.getPrivate(), "CN=Sertifikatcompagniet CA", "CN=Sertifikatcompagniet Intermediate", validStart, validEnd, true);
        final X509Certificate signatureCertificate = generateCertificate(signatureKeys.getPublic(), intermediateKeys.getPrivate(), "CN=Sertifikatcompagniet Intermediate", "CN=Sertifikatcompagniet Testsertifikat", validStart, validEnd, false);


        CertificateBucket rootCertificates = new SimpleCertificateBucket(rootCertificate);
        CertificateBucket intermediateCertificates = new SimpleCertificateBucket(intermediateCertificate);

        Validator validator = ValidatorBuilder.newInstance()
                .addRule(new ChainRule(rootCertificates, intermediateCertificates))
                .build();

        validator.validate(signatureCertificate);
        validator.validate(intermediateCertificate);
        validator.validate(rootCertificate, SimpleReport.newInstance());
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
