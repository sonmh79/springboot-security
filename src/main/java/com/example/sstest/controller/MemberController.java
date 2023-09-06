package com.example.sstest.controller;

import com.example.sstest.auth.domain.MySaml2Authentication;
import com.example.sstest.controller.data.Data;
import com.example.sstest.controller.reponse.ResponseDTO;
import com.example.sstest.domain.Member;
import com.example.sstest.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

/**
 * {@code MemberController}는 회원과 관련된 API를 처리하는 컨트롤러입니다.
 *
 * @author sonmh79
 */
@RestController
@RequestMapping("/api/v1/members")
@RequiredArgsConstructor
@Slf4j
public class MemberController {

    private static final String SUCCESS = "success";
    private final MemberService memberService;

    @GetMapping("/login")
    public ResponseEntity<ResponseDTO> login(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        HashMap<String,String> map = new HashMap<>();
        map.put("name",principal.getFirstAttribute("fullName"));
        log.info("name: " + principal.getFirstAttribute("fullName"));
        log.info("username: " + principal.getFirstAttribute("userName"));
        log.info("email: " + principal.getFirstAttribute("email"));
        log.info("role: " + principal.getAttribute("urn:mace:dir:attribute-def:groups"));
        String saml2Response = ((MySaml2Authentication) SecurityContextHolder.getContext().getAuthentication()).getSaml2Response();
        Data loginData = memberService.adminLogin(principal, saml2Response, httpServletRequest, httpServletResponse);

        ResponseDTO responseDTO = ResponseDTO.builder()
                .status(SUCCESS)
                .message("admin 로그인 성공")
                .data(loginData)
                .build();

        log.info(SecurityContextHolder.getContext().getAuthentication().toString());

        return new ResponseEntity<>(responseDTO, HttpStatus.OK);
    }

    /**
     * 관리자 계정 로그인 처리합니다.
     *
     * @param email            관리자 계정의 email
     * @param httpServletRequest
     * @param httpServletResponse
     * @return 성공 시 로그인 처리된 관리자 정보를 {@code ResponseEntity}로 반환합니다.
     */
    @PostMapping("/admin-login")
    public ResponseEntity<ResponseDTO> adminLogin(@RequestBody String email, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        Data loginData = memberService.adminLogin(new Saml2AuthenticatedPrincipal() {
            @Override
            public String getName() {
                return "admin";
            }
        }, "", httpServletRequest, httpServletResponse);

        ResponseDTO responseDTO = ResponseDTO.builder()
                .status(SUCCESS)
                .message("admin 로그인 성공")
                .data(loginData)
                .build();

        return new ResponseEntity<>(responseDTO, HttpStatus.OK);
    }

    /**
     * 로그아웃 처리합니다.
     *
     * @param httpServletRequest
     * @param httpServletResponse
     * @return 성공 시 메시지를 반환합니다.
     */
    @PatchMapping("/logout")
    public ResponseEntity<ResponseDTO> logoutMember(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        Member member = (Member) httpServletRequest.getAttribute("member");

        memberService.deleteRefreshToken(member.getId(), httpServletRequest, httpServletResponse);

        ResponseDTO responseDTO = ResponseDTO.builder()
                .status(SUCCESS)
                .message("로그아웃 성공")
                .build();

        return new ResponseEntity<>(responseDTO, HttpStatus.OK);
    }

    /**
     * access token을 재발급합니다.
     *
     * @param httpServletRequest
     * @param httpServletResponse
     * @return 성공 시 재발급한 access token을 {@code ResponseEntity}로 반환합니다.
     */
    @GetMapping("/access-token")
    public ResponseEntity<ResponseDTO> reissueAccessToken(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        Data data = memberService.reissueAccessToken(httpServletRequest, httpServletResponse);

        ResponseDTO responseDTO = ResponseDTO.builder()
                .status(SUCCESS)
                .message("access token 재발급 성공")
                .data(data)
                .build();

        return new ResponseEntity<>(responseDTO, HttpStatus.OK);
    }

}