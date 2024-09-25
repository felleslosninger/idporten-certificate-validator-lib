package no.digdir.certvalidator.rule;

import no.digdir.certvalidator.api.CertificateValidationException;
import no.digdir.certvalidator.api.FailedValidationException;
import no.digdir.certvalidator.api.Property;
import no.digdir.certvalidator.api.Report;
import no.digdir.certvalidator.util.SimpleProperty;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Validator checking certificate policies. At least one of the accepted policies must be present in the certificate.
 * An accepted policy must be specified either as a complete policy string or as a wildcard policy string ending with a "*".
 */
public class PolicyRule extends AbstractRule {

    public static final Property<Set<String>> POLICY = SimpleProperty.create();

    private final Set<String> acceptedPolicies = new HashSet<>();

    /**
     * Creates rule instance
     * @param acceptedPolicies accepted certificate policies
     */
    public PolicyRule(Set<String> acceptedPolicies) {
        this.acceptedPolicies.addAll(acceptedPolicies);
    }

    /**
     * Creates rule instance
     * @param acceptedPolicies accepted certificate policies
     */
    public PolicyRule(String... acceptedPolicies) {
        this.acceptedPolicies.addAll(Arrays.asList(acceptedPolicies));
    }

    /**
     * Validates certificate policies. At least one of the accepted policies must be present in the certificate.
     */
    @Override
    public Report validate(X509Certificate certificate, Report report) throws CertificateValidationException {
        final Set<String> matchingPolicies = new HashSet<>();
        try {
            byte[] certificatePoliciesExtensionValues = certificate.getExtensionValue(org.bouncycastle.asn1.x509.Extension.certificatePolicies.getId());
            CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(JcaX509ExtensionUtils.parseExtensionValue(certificatePoliciesExtensionValues));
            Set<String> certificatePolicyIdentifiers =
                    Arrays.stream(certificatePolicies.getPolicyInformation())
                    .map(PolicyInformation::getPolicyIdentifier)
                    .map(ASN1ObjectIdentifier::getId)
                    .collect(Collectors.toSet());
            matchingPolicies.addAll(findMatchingPolicies(certificatePolicyIdentifiers));
        } catch (IOException e) {
            throw new FailedValidationException(e.getMessage(), e);
        }
        if (matchingPolicies.isEmpty()) {
            throw new FailedValidationException("No accepted policies found in certificate.");
        }
        report.set(POLICY, matchingPolicies);
        return report;
    }

    private Set<String> findMatchingPolicies(Set<String> certificatePolicyIdentifiers) {
        Set<String> matchingPolicies = new HashSet<>();
        for (String acceptedPolicy : acceptedPolicies) {
            for (String certificatePolicyIdentifier : certificatePolicyIdentifiers) {
                if (certificatePolicyIdentifier.equals(acceptedPolicy)) {
                    matchingPolicies.add(certificatePolicyIdentifier);
                } else if (isWildcardPolicy(acceptedPolicy) && wildcardPolicyMatches(acceptedPolicy, certificatePolicyIdentifier)) {
                    matchingPolicies.add(certificatePolicyIdentifier);
                }
            }
        }
        return matchingPolicies;
    }

    private boolean isWildcardPolicy(String policy) {
        return policy.endsWith("*");
    }

    private boolean wildcardPolicyMatches(String policy, String certificatePolicyIdentifier) {
        return certificatePolicyIdentifier.startsWith(policy.substring(0, policy.length() - 1));
    }

}
