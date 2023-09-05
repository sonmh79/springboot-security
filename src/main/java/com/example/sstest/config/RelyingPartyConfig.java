package com.example.sstest.config;

import org.opensaml.security.x509.X509Support;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

import java.io.File;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

@Configuration
public class RelyingPartyConfig {

    @Value("${saml.ssafy.verification-key-path}")
    private String keyPath;

    @Value("${saml.ssafy.entity-id}")
    private String entityId;

    @Value("${saml.ssafy.service-location}")
    private String serviceLocation;

    @Value("${private.key}")
    RSAPrivateKey privateKey;

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrations() throws Exception {

        return new InMemoryRelyingPartyRegistrationRepository(registration());
    }

    @Bean
    public RelyingPartyRegistration registration() throws CertificateException {
        ClassLoader classLoader = getClass().getClassLoader();
        File verificationKey = new File(classLoader.getResource(keyPath).getFile());
        X509Certificate certificate = X509Support.decodeCertificate(verificationKey);
        Saml2X509Credential credential = Saml2X509Credential.verification(certificate);
        Saml2X509Credential myCredential = Saml2X509Credential.signing(privateKey, certificate);
        RelyingPartyRegistration registration = RelyingPartyRegistration
                .withRegistrationId("ssafy-saml")
                .assertingPartyDetails(party -> party
                        .entityId(entityId)
                        .singleSignOnServiceLocation(serviceLocation)
                        .signingAlgorithms((sign) -> sign.add(SignatureConstants.ALGO_ID_ENCODING_BASE64))
                        .wantAuthnRequestsSigned(false)
                        .verificationX509Credentials(c -> c.add(credential))
                )
                .singleLogoutServiceLocation("{baseUrl}/logout/saml2/slo")
                .signingX509Credentials((signing) -> signing.add(myCredential))
                .build();
        return registration;
    }
}
