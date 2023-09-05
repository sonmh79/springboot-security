package com.example.sstest.config;

import com.example.sstest.jwt.AuthTokenProvider;
import com.example.sstest.jwt.TokenAccessDeniedHandler;
import com.example.sstest.jwt.TokenAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationRequestFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.HeaderWriterLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity(debug = false)
@RequiredArgsConstructor
public class SAMLSecurityConfig {

    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    private final AuthTokenProvider tokenProvider;
    private final TokenAccessDeniedHandler tokenAccessDeniedHandler;

    static {
        OpenSamlInitializationService.initialize();
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
        authenticationProvider.setResponseAuthenticationConverter(responseToken -> {
            Saml2Authentication authentication = OpenSaml4AuthenticationProvider
                    .createDefaultResponseAuthenticationConverter()
                    .convert(responseToken);
            Assertion assertion = responseToken.getResponse().getAssertions().get(0);
            String username = assertion.getSubject().getNameID().getValue();
//            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
//            return MySaml2Authentication(userDetails, authentication);
            return authentication;
        });

        return http
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .authorizeRequests(authorize ->
                        authorize
                                .antMatchers("/api/v1/members/login").authenticated()
                                .antMatchers("/api/test").authenticated()
                                .anyRequest().permitAll()
                ).saml2Login(withDefaults())
                .saml2Logout(withDefaults())
                .logout(logout -> {
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
                .addFilterBefore(tokenAuthenticationFilter(), Saml2WebSsoAuthenticationRequestFilter.class)
                .exceptionHandling().accessDeniedHandler(tokenAccessDeniedHandler)
                .and()
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

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter(tokenProvider);
    }

}
