package com.example.sstest.service;

import com.example.sstest.auth.domain.AppProperties;
import com.example.sstest.auth.domain.MySaml2Authentication;
import com.example.sstest.auth.domain.PrincipalDetails;
import com.example.sstest.controller.data.LoginData;
import com.example.sstest.controller.data.ReissuedAccessTokenData;
import com.example.sstest.domain.Member;
import com.example.sstest.exception.MemberNotFoundException;
import com.example.sstest.exception.UnAuthorizedException;
import com.example.sstest.jwt.AuthToken;
import com.example.sstest.jwt.AuthTokenProvider;
import com.example.sstest.repository.MemberRepository;
import com.example.sstest.util.CookieUtil;
import com.example.sstest.util.HeaderUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * {@code MemberService}는 로그인을 제외한 모든 유저 관련 로직을 처리하는 서비스입니다.
 *
 * @author sonmh79
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MemberService {

    private static final String REFRESH_TOKEN = "refreshToken";
    private static final String ROLE = "ROLE_USER";

    private final MemberRepository memberRepository;
    private final AuthTokenProvider tokenProvider;
    private final AppProperties appProperties;
    private final AuthTokenProvider authTokenProvider;

    @Value("${app.auth.refresh-token-expiry}")
    private long refreshTokenExpiry;

    /**
     * 관리자 계정 로그인을 처리합니다.
     *
     * @param principal  로그인을 요청한 유저 정보
     * @param httpServletRequest
     * @param httpServletResponse
     * @return 성공 시 닉네임, access token, isFirst를 담은 SocialLoginData 타입의 객체를 반환합니다.
     */
    @Transactional
    public LoginData adminLogin(Saml2AuthenticatedPrincipal principal, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        String email = principal.getFirstAttribute("email");
        String saml2Response = ((MySaml2Authentication) SecurityContextHolder.getContext().getAuthentication()).getSaml2Response();

        Optional<Member> member = memberRepository.findByEmail(email);
        Member loginMember;
        if (member.isEmpty()) {
            loginMember = createMember(principal);
        } else {
            loginMember = member.get();
        }

        Date now = new Date();
        AuthToken accessToken = authTokenProvider.createSaml2AuthToken(
                email,
                loginMember.getRole(),
                new Date(now.getTime() + appProperties.getAuth().getTokenExpiry())
        );

        AuthToken refreshToken = makeRefreshToken();

        loginMember.saveRefreshToken(refreshToken.getToken());
        memberRepository.save(loginMember);
        LoginData loginData = LoginData.builder().memberId(loginMember.getId()).name(loginMember.getName()).accessToken(accessToken.getToken()).isFirst(false).build();

        int cookieMaxAge = (int) refreshTokenExpiry / 60;
        CookieUtil.deleteCookie(httpServletRequest, httpServletResponse, REFRESH_TOKEN);
        CookieUtil.addCookie(httpServletResponse, REFRESH_TOKEN, refreshToken.getToken(), cookieMaxAge);

        return loginData;
    }

    @Transactional
    private Member createMember(Saml2AuthenticatedPrincipal principal) {
        String email = principal.getFirstAttribute("email");
        String name = principal.getFirstAttribute("fullName");
        String userName = principal.getFirstAttribute("userName");
        List<String> roles =  principal.getAttribute("urn:mace:dir:attribute-def:groups");
        String role = new String();
        for (String str : roles) {
            role += str;
            role += " ";
        }

        Member member = Member.builder()
                .name(name)
                .username(userName)
                .email(email)
                .role(role)
                .active(true)
                .build();
        memberRepository.save(member);
        return member;
    }

    /**
     * 로그아웃 시 호출되는 메서드로 DB에 저장된 refresh token을 삭제합니다.
     *
     * @param memberId              refresh token을 삭제할 member id
     * @param httpServletRequest
     * @param httpServletResponse
     */
    @Transactional
    public void deleteRefreshToken(Integer memberId, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        Member member = memberRepository.findById(String.valueOf(memberId)).orElseThrow(MemberNotFoundException::new);
        member.deleteRefreshToken();
        memberRepository.save(member);
        CookieUtil.deleteCookie(httpServletRequest, httpServletResponse, REFRESH_TOKEN);
    }

    /**
     * access token을 재발급합니다.
     *
     * @param httpServletRequest
     * @param httpServletResponse
     * @return 성공 시 재발급한 access token을 담은 ReissuedAccessTokenData 타입의 객체를 반환합니다.
     */
    @Transactional
    public ReissuedAccessTokenData reissueAccessToken(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {

        String headerAccessToken = HeaderUtil.getAccessToken(httpServletRequest);

        AuthToken authHeaderAccessToken = tokenProvider.convertAuthToken(headerAccessToken);
        Authentication authentication = tokenProvider.getExpiredUser(authHeaderAccessToken);

        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

        Member member = principalDetails.getMember();
        String cookieRefreshToken = CookieUtil.getCookie(httpServletRequest, REFRESH_TOKEN)
                .map(Cookie::getValue)
                .orElse(null);

        try {
            if (cookieRefreshToken == null) {
                throw new UnAuthorizedException("쿠키에 refresh token이 없습니다. 다시 로그인 해주세요.");
            }

            String refreshToken = member.getRefreshToken();

            if (!cookieRefreshToken.equals(refreshToken)) {
                deleteCookieRefreshToken(httpServletRequest, httpServletResponse);
                throw new UnAuthorizedException("DB에 저장되어 있는 refreshToken과 다릅니다. 다시 로그인 해주세요.");
            }

            log.info("DB에 저장한 리프레시 토큰 : {}", refreshToken);

        } catch (NullPointerException e) {
            deleteCookieRefreshToken(httpServletRequest, httpServletResponse);
            throw new UnAuthorizedException("refresh token이 만료되었습니다. 다시 로그인 해주세요.");
        }

        log.debug("쿠키에 담긴 refreshToken : {}", cookieRefreshToken);

        AuthToken accessToken = makeAccessToken(member.getId().toString());

        log.info("정상적으로 액세스토큰 재발급!!!");

        return ReissuedAccessTokenData.builder().accessToken(accessToken.getToken()).build();
    }

    /**
     * access token을 발급합니다.
     *
     * @param memberId access token을 생성할 member id
     * @return 성공 시 발급된 access token을 AuthToken 타입의 객체로 반환합니다.
     */
    public AuthToken makeAccessToken(String memberId) {
        Date now = new Date();
        return tokenProvider.createAuthToken(
                memberId,
                ROLE,
                new Date(now.getTime() + appProperties.getAuth().getTokenExpiry())
        );
    }

    /**
     * refresh token을 발급합니다.
     *
     * @return 성공 시 생성한 refresh token을 AuthToken 타입의 객체로 반환합니다.
     */
    public AuthToken makeRefreshToken() {
        Date now = new Date();
        return tokenProvider.createAuthToken(new Date(now.getTime() + refreshTokenExpiry));
    }

    /**
     * 쿠키에 담긴 refresh token을 삭제합니다.
     *
     * @param httpServletRequest
     * @param httpServletResponse
     */
    public void deleteCookieRefreshToken(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        CookieUtil.deleteCookie(httpServletRequest, httpServletResponse, REFRESH_TOKEN);
    }

}