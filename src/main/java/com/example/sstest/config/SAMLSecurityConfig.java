package com.example.sstest.config;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.impl.AuthnRequestMarshaller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SAMLSecurityConfig {

    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    static {
        OpenSamlInitializationService.requireInitialize(factory -> {
            AuthnRequestMarshaller marshaller = new AuthnRequestMarshaller() {
                @Override
                public Element marshall(XMLObject object, Element element) throws MarshallingException {
                    configureAuthnRequest((AuthnRequest) object);
                    return super.marshall(object, element);
                }

                public Element marshall(XMLObject object, Document document) throws MarshallingException {
                    configureAuthnRequest((AuthnRequest) object);
                    return super.marshall(object, document);
                }

                private void configureAuthnRequest(AuthnRequest authnRequest) {
                    authnRequest.setForceAuthn(true);
                }
            };

            factory.getMarshallerFactory().registerMarshaller(AuthnRequest.DEFAULT_ELEMENT_NAME, marshaller);
        });
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        return http
                .authorizeRequests(authorize ->
                        authorize.antMatchers("/")
                                .permitAll()
                                .anyRequest()
                                .authenticated()
                ).saml2Login(withDefaults())
                .build();
    }

    @Bean
    Saml2AuthenticationRequestResolver authenticationRequestResolver(RelyingPartyRegistrationRepository registrations) {
        RelyingPartyRegistrationResolver registrationResolver = new DefaultRelyingPartyRegistrationResolver(registrations);
        OpenSaml4AuthenticationRequestResolver authenticationRequestResolver = new OpenSaml4AuthenticationRequestResolver(registrationResolver);
        authenticationRequestResolver.setAuthnRequestCustomizer((context) -> context
                .getAuthnRequest().setForceAuthn(true));
        return authenticationRequestResolver;
    }

}
