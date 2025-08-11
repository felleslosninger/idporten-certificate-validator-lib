package no.idporten.validator.certificate.util;

import no.idporten.validator.certificate.api.Property;

/**
 * @author erlend
 */
public class SimpleProperty<T> implements Property<T> {

    public static <T> Property<T> create() {
        return (Property<T>) new SimpleProperty<>();
    }

    private SimpleProperty() {
        // No action.
    }
}
