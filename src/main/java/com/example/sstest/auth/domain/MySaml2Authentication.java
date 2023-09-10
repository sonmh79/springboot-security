package com.example.sstest.auth.domain;

import lombok.Getter;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;

import java.util.List;

public class MySaml2Authentication extends Saml2Authentication {
    @Getter
    String saml2Response;
    Saml2Authentication authentication;

    public MySaml2Authentication(String saml2Response, Saml2Authentication authentication, List<GrantedAuthority> authorities) {
        super((AuthenticatedPrincipal) authentication.getPrincipal(),saml2Response,authorities);
        this.saml2Response = saml2Response;
        this.authentication = authentication;
    }

}