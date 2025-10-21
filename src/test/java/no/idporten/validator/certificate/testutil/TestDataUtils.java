package no.idporten.validator.certificate.testutil;

import com.nimbusds.jose.util.Base64;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.platform.commons.JUnitException;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Utilities for test data.
 */
public class TestDataUtils {


    public static List<Base64> toBase64(X509Certificate[] chain) {
        var output = new ArrayList<Base64>(chain.length);
        var encoder = java.util.Base64.getEncoder();

        try {
            for (X509Certificate cert : chain) {
                String encodedCert = encoder.encodeToString(cert.getEncoded());
                output.add(Base64.from(encodedCert));
            }

        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
        return output;
    }

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


    public static X509Certificate generateCertificate(PublicKey subjectKey, PrivateKey signingKey, String issuer, String subject, Date notBefore, Date notAfter, boolean isCA) {
        X500Name iss = new X500Name(issuer);
        X500Name sub = new X500Name(subject);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        try {
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(iss, serial, notBefore, notAfter, sub, subjectKey);
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(signingKey);

            X509CertificateHolder certHolder = builder
                    // OID for Key Usage
                    .addExtension(new ASN1ObjectIdentifier("2.5.29.15"),true, new KeyUsage(getKeyUsageForCA(isCA)).toASN1Primitive())
                    // OID for Basic Constraint
                    .addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, new org.bouncycastle.asn1.x509.BasicConstraints(isCA))
                    .build(signer);
            return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certHolder);

        } catch (OperatorCreationException | CertificateException | CertIOException e) {
            throw new RuntimeException(e);
        }
    }



    /**
     * Downloads and parses an X509 certificate from the given URL.
     *
     * @param certUrl The URL of the certificate to download.
     * @return The parsed X509Certificate.
     */
    public static X509Certificate downloadAndParse(String certUrl) {
        try (InputStream in = URI.create(certUrl).toURL().openStream()) {
            byte[] data = in.readAllBytes();
            String content = new String(data);

            if (content.contains("-----BEGIN CERTIFICATE-----")) {
                String base64 = content.replaceAll("-----BEGIN CERTIFICATE-----", "")
                        .replaceAll("-----END CERTIFICATE-----", "")
                        .replaceAll("\\s", "");
                data = java.util.Base64.getDecoder().decode(base64);
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            try (InputStream certIn = new java.io.ByteArrayInputStream(data)) {
                return (X509Certificate) cf.generateCertificate(certIn);
            }
        } catch (IOException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

}
