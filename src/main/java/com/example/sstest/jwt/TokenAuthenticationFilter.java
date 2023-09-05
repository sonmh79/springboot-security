package com.example.sstest.jwt;

import com.example.sstest.auth.domain.PrincipalDetails;
import com.example.sstest.controller.reponse.ResponseDTO;
import com.example.sstest.exception.JwtExpiredException;
import com.example.sstest.util.HeaderUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final AuthTokenProvider tokenProvider;
    private final List<String> excludedUris = Arrays.asList("/api/v1/auth/members/access-token");

    @Autowired
    private RelyingPartyRegistration relyingPartyRegistration;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (skipFilterForUri(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String headerToken = HeaderUtil.getAccessToken(request);
        String samlResponse = HeaderUtil.getAccessToken(request);
        AuthToken token = tokenProvider.convertAuthToken(headerToken);

        try {
            if (token.getToken() != null && token.validate()) {

//                Authentication authentication = tokenProvider.getAuthentication(token);
//                PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
//                request.setAttribute("member", principalDetails.getMember());

//                log.debug("TokenAuthenticationFilter로 접근한 member id(PK) : {}, 닉네임 : {}", principalDetails.getMember().getId(), principalDetails.getMember().getName());
                log.info("TokenAuthFilter 들어옴");
                SecurityContextHolder.getContext().setAuthentication(new Saml2AuthenticationToken(relyingPartyRegistration,samlResponse));
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
            return;
        }
        filterChain.doFilter(request, response);

    }

    private boolean skipFilterForUri(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        return excludedUris.stream().anyMatch(requestURI::equals);
    }

}