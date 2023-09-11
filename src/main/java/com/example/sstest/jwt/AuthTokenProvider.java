package com.example.sstest.jwt;

import com.example.sstest.domain.Member;
import com.example.sstest.exception.MemberNotFoundException;
import com.example.sstest.exception.TokenValidFailedException;
import com.example.sstest.exception.UnAuthorizedException;
import com.example.sstest.repository.MemberRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

    public AuthToken createSaml2AuthToken(Date expiry) {
        return new AuthToken(expiry, key);
    }

    public AuthToken createSaml2AuthToken(Member member, Date expiry) {
        return new AuthToken(member, expiry, key);
    }

    public AuthToken convertAuthToken(String token) {
        return new AuthToken(token, key);
    }

    public Saml2Authentication getExpiredUser(AuthToken authToken) {
        Claims claims = authToken.getExpiredTokenClaims();

        if (claims == null) {
            throw new UnAuthorizedException("다시 로그인 해주세요.");
        }
        return getRealSaml2Authentication(claims, authToken);
    }

    public Saml2Authentication getSaml2Authentication(AuthToken authToken) {
        if (authToken.validate()) {
            Claims claims = authToken.getTokenClaims();
            return getRealSaml2Authentication(claims, authToken);
        } else {
            throw new TokenValidFailedException();
        }
    }

    private Saml2Authentication getRealSaml2Authentication(Claims claims, AuthToken authToken) {
        List<String> authorities = new ArrayList<>();
        StringTokenizer st = new StringTokenizer(claims.get(AUTHORITIES_KEY).toString());
        while (st.hasMoreTokens()) {
            authorities.add(st.nextToken());
        }
        String email = claims.get("email").toString();
        Member loginMember = memberRepository.findByEmail(email).orElseThrow(MemberNotFoundException::new);
        HashMap<String, List<Object>> map = new HashMap<>();
        map.put("member", Arrays.asList(loginMember));
        return new Saml2Authentication(new DefaultSaml2AuthenticatedPrincipal(loginMember.getName(), map), "saml2Response", authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
    }
}