package no.idporten.validator.certificate.testutil;

public class TestDataConstants {
    public enum HttpResource {
        TEST_CERTIFICATE_COMMFIDES_G3_LEGAL_PERSON("https://crt.test.commfides.com/G3/CommfidesLegalPersonCA-G3-TEST.crt");

        private final String url;

        HttpResource(String url) {
            this.url = url;
        }

        public String url() {
            return url;
        }
    }



}

