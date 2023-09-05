package com.example.sstest.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@Slf4j
public class SamlController {


    @GetMapping("/api/test")
    public ResponseEntity<Map> test(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal) {
        HashMap<String,String> map = new HashMap<>();
        map.put("name",principal.getFirstAttribute("fullName"));
        log.info("name: " + principal.getFirstAttribute("fullName"));
        log.info("username: " + principal.getFirstAttribute("userName"));
        log.info("email: " + principal.getFirstAttribute("email"));
        log.info("role: " + principal.getAttribute("urn:mace:dir:attribute-def:groups"));
        return new ResponseEntity<>(map,HttpStatus.OK);
    }

}