package com.example.sstest.config;

import com.example.sstest.auth.domain.MySaml2Authentication;
import com.example.sstest.jwt.AuthTokenProvider;
import com.example.sstest.jwt.TokenAuthFilter;
import lombok.RequiredArgsConstructor;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.HeaderWriterLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity(debug = false)
@RequiredArgsConstructor
public class SecurityConfig {

    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    private final AuthTokenProvider tokenProvider;

    static {
        OpenSamlInitializationService.initialize();
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        return http
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .authorizeRequests(
                        authorize -> authorize
                                .antMatchers("/api/v1/members/login").authenticated()
                                .anyRequest().permitAll()
                )
                .saml2Login(saml2 -> saml2
                        .loginProcessingUrl("/api/v1/login/sso/saml2/{registrationId}")
                        .authenticationManager(new ProviderManager(saml2AuthenticationProvider()))
                )
                .saml2Logout(withDefaults())
                .logout(logout ->
                {
                    LogoutHandler successLogoutHandler = (request, response, authentication) -> {
                        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
                        logoutHandler.logout(request,response,authentication);
                        SecurityContextHolder.clearContext();

                        try {
                            response.sendRedirect("/");
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    };
                    logout
                            .deleteCookies("JSESSIONID")
                            .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                            .logoutSuccessUrl("/")
                            .clearAuthentication(true)
                            .addLogoutHandler(successLogoutHandler)
                            .addLogoutHandler(new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter(ClearSiteDataHeaderWriter.Directive.COOKIES)))
                            .invalidateHttpSession(true);
                })
                .addFilterAfter(new TokenAuthFilter(tokenProvider), HeaderWriterFilter.class)
                .build();
    }

    OpenSaml4AuthenticationProvider saml2AuthenticationProvider() {
        OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
        authenticationProvider.setResponseAuthenticationConverter(responseToken -> {
            Saml2Authentication authentication = OpenSaml4AuthenticationProvider
                    .createDefaultResponseAuthenticationConverter()
                    .convert(responseToken);
            Assertion assertion = responseToken.getResponse().getAssertions().get(0);
            AttributeStatement attributeStatement = assertion.getAttributeStatements().get(0);
            List<GrantedAuthority> authorities = attributeStatement.getAttributes().get(0).getAttributeValues().stream()
                    .map(xmlObject -> xmlObject.getDOM().getTextContent())
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
            String saml2Response = responseToken.getToken().getSaml2Response();
            return new MySaml2Authentication(saml2Response, authentication, authorities);
        });

        return authenticationProvider;
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
