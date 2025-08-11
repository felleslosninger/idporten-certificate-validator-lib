package no.idporten.validator.certificate.api;

/**
 * @author erlend
 */
public interface ErrorHandler {

    void handle(CertificateValidationException e) throws FailedValidationException;

}
