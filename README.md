# idporten-certificate-validator-lib
![Build Status](https://github.com/felleslosninger/idporten-certificate-validator-lib/actions/workflows/call-maventests.yml/badge.svg)

Dette biblioteket inneholder en implementasjon av et sertifikatvalideringsbibliotek for ID-porten. Det er basert på [Bouncy Castle](https://www.bouncycastle.org/java.html).

## Forutsetninger

- Java 21
- Maven

## Bruk

Man bygger prosjektet

    mvn assembly:assembly

Ta i bruk i ditt prosjekt ved å legge til avhengighet i pom.xml:
```xml
<dependency>
    <groupId>no.idporten.validator.certificate</groupId>
    <artifactId>idporten-certvalidator</artifactId>
</dependency>
```
Bruk [ValidatorBuilder](src/main/java/no/idporten/validator/certificate/ValidatorBuilder.java) for å konstruere en [Validator](src/main/java/no/idporten/validator/certificate/Validator.java) med de reglene som ønskes fra javaklassene i pakken [src/main/java/no/idporten/validator/certificate/rule](src/main/java/no/idporten/validator/certificate/rule).
