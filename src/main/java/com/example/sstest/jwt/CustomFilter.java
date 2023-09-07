package com.example.sstest.jwt;

import com.example.sstest.controller.reponse.ResponseDTO;
import com.example.sstest.exception.JwtExpiredException;
import com.example.sstest.util.HeaderUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class CustomFilter extends AbstractAuthenticationProcessingFilter {

    private final AuthTokenProvider tokenProvider;

    @Autowired
    private RelyingPartyRegistration relyingPartyRegistration;

    public CustomFilter(RequestMatcher requiresAuthenticationRequestMatcher, AuthTokenProvider tokenProvider) {
        super(requiresAuthenticationRequestMatcher);
        this.tokenProvider = tokenProvider;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        String headerToken = HeaderUtil.getAccessToken(request);
        AuthToken token = tokenProvider.convertAuthToken(headerToken);

        try {
            if (token.getToken() != null && token.validate()) {

                log.info("CustomAuthFilter 들어옴");
                Saml2Authentication authentication = tokenProvider.getSaml2Authentication(token);
                return getAuthenticationManager().authenticate(authentication);
            }

        } catch (JwtExpiredException e) {
            ObjectMapper objectMapper = new ObjectMapper();
            ResponseDTO responseDTO = ResponseDTO.builder()
                    .status("fail")
                    .message("reissue")
                    .build();
            response.setCharacterEncoding("utf-8");
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            // writeValueAsString() : Object to JSON in String
            response.getWriter().write(objectMapper.writeValueAsString(responseDTO));
            return null;
        }

        return null;
    }

}
