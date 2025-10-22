package no.idporten.validator.certificate.testutil;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.platform.commons.JUnitException;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Utilities for test data.
 */
public class TestDataUtils {


    public static KeyPair generateRSAKeyPair() {
        try {
            final var keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new JUnitException("Unable to generate RSA key pair", e);
        }
    }

    private static int getKeyUsageForCA(boolean isCA) {
        return isCA ? KeyUsage.keyCertSign : KeyUsage.digitalSignature;
    }


    /**
     * Generates an X509 certificate.
     *
     * @param subjectKey the public key for the subject.
     * @param signingKey the private key used to sign the certificate.
     * @param issuer     the issuer distinguished name.
     * @param subject    the subject distinguished name.
     * @param notBefore  date when the certificate was issued
     * @param notAfter   date when the certificate expires
     * @param isCA       whether the certificate is for a CA. Will set required extensions.
     * @param isRoot     weither the certificate is a root certificate. Will set required extensions.
     * @return the generated X509 certificate.
     */
    public static X509Certificate generateCertificate(PublicKey subjectKey, PrivateKey signingKey, String issuer, String subject, Date notBefore, Date notAfter, boolean isCA, boolean isRoot) {
        X500Name sub = new X500Name(subject);
        X500Name iss = isRoot ? sub : new X500Name(issuer); // Self-signed if root
        BigInteger serial = new BigInteger(64, new SecureRandom());


        if (isRoot && !isCA) {
            throw new IllegalArgumentException("When setting isRoot to true, isCA must also be true, to generate realistic root CA certificates.");
        }

        try {
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(iss, serial, notBefore, notAfter, sub, subjectKey);
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(signingKey);

            JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(subjectKey));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(getKeyUsageForCA(isCA)).toASN1Primitive());
            builder.addExtension(Extension.basicConstraints, true, new org.bouncycastle.asn1.x509.BasicConstraints(isCA));

            if (isRoot) {
                // AKI must match SKI for a root certificate
                builder.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(subjectKey));
            }

            X509CertificateHolder certHolder = builder.build(signer);
            return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certHolder);

        } catch (OperatorCreationException | CertificateException | CertIOException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
