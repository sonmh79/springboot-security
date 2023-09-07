package com.example.sstest.jwt;

import com.example.sstest.auth.domain.PrincipalDetails;
import com.example.sstest.exception.TokenValidFailedException;
import com.example.sstest.exception.UnAuthorizedException;
import com.example.sstest.repository.MemberRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;

import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class AuthTokenProvider {
    private final Key key;
    private static final String AUTHORITIES_KEY = "role";
    private final MemberRepository memberRepository;

    /**
     * 객체 초기화
     *
     * @param secret : jwt의 secret
     */
    public AuthTokenProvider(String secret, MemberRepository memberRepository) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
        this.memberRepository = memberRepository;
    }

    public AuthToken createAuthToken(Date expiry) {
        return new AuthToken(expiry, key);
    }

    public AuthToken createAuthToken(String id, String role, Date expiry) {
        return new AuthToken(id, role, expiry, key);
    }

    public AuthToken createSaml2AuthToken(String id, String role, Date expiry) {
        return new AuthToken(id, role, expiry, key);
    }

    public AuthToken convertAuthToken(String token) {
        return new AuthToken(token, key);
    }

    public Authentication getAuthentication(AuthToken authToken) {

        if (authToken.validate()) {
            Claims claims = authToken.getTokenClaims();
            return getRealAuthentication(claims, authToken);
        } else {
            throw new TokenValidFailedException();
        }
    }

    public Authentication getExpiredUser(AuthToken authToken) {

        Claims claims = authToken.getExpiredTokenClaims();

        if (claims == null) {
            throw new UnAuthorizedException("다시 로그인 해주세요.");
        }
        return getRealAuthentication(claims, authToken);
    }

    public Authentication getRealAuthentication(Claims claims, AuthToken authToken) {

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(new String[]{claims.get(AUTHORITIES_KEY).toString()})
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        log.debug("claims subject := [{}]", claims.getSubject());
        PrincipalDetails principalDetails = new PrincipalDetails(memberRepository.findById(String.valueOf(claims.get("id"))).orElse(null));
        return new UsernamePasswordAuthenticationToken(principalDetails, authToken, authorities);
    }

    public Saml2Authentication getSaml2Authentication(AuthToken authToken) {
        if (authToken.validate()) {
            Claims claims = authToken.getTokenClaims();
            return getRealSam2Authentication(claims, authToken);
        } else {
            throw new TokenValidFailedException();
        }
    }

    private Saml2Authentication getRealSam2Authentication(Claims claims, AuthToken authToken) {
        List<String> authorities = new ArrayList<>();
        StringTokenizer st = new StringTokenizer(claims.get(AUTHORITIES_KEY).toString());
        while (st.hasMoreTokens()) {
            authorities.add(st.nextToken());
        }
        return new Saml2Authentication(new DefaultSaml2AuthenticatedPrincipal(claims.get("email").toString(), new HashMap<>()), claims.get("saml2Response").toString(), authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
    }
}