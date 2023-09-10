package com.example.sstest.jwt;

import com.example.sstest.controller.reponse.ResponseDTO;
import com.example.sstest.exception.JwtExpiredException;
import com.example.sstest.util.HeaderUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.AccessDeniedException;

@Slf4j
@RequiredArgsConstructor
public class TokenAuthFilter extends OncePerRequestFilter {

    private final AuthTokenProvider tokenProvider;
    private final AntPathMatcher antPathMatcher = new AntPathMatcher();
    private final String[] authUrls = {"/api/v1/**/auth/**"};

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String headerToken = HeaderUtil.getAccessToken(request);
        AuthToken token = tokenProvider.convertAuthToken(headerToken);

        for (String authUrl : authUrls) {
            if (antPathMatcher.match(authUrl,request.getRequestURI())) {
                try {
                    if (token.getToken() != null && token.validate()) {
                        Saml2Authentication authentication = tokenProvider.getSaml2Authentication(token);
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                        request.setAttribute("member",((DefaultSaml2AuthenticatedPrincipal) authentication.getPrincipal()).getFirstAttribute("member"));
                    } else {
                        throw new AccessDeniedException("Access Token이 필요합니다.");
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
                    response.getWriter().write(objectMapper.writeValueAsString(responseDTO));
                    return;

                } catch (AccessDeniedException e) {
                    ObjectMapper objectMapper = new ObjectMapper();
                    ResponseDTO responseDTO = ResponseDTO.builder()
                            .status("fail")
                            .message("denied")
                            .build();
                    response.setCharacterEncoding("utf-8");
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    response.setStatus(HttpStatus.FORBIDDEN.value());
                    response.getWriter().write(objectMapper.writeValueAsString(responseDTO));
                    return;
                }
            }
            filterChain.doFilter(request,response);
        }
    }

}
