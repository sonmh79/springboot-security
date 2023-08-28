package com.example.sstest.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@Slf4j
public class SamlController {

    @RequestMapping("/")
    public String index() {
        return "home";
    }

    @RequestMapping("/secured/hello")
    public String hello(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
        model.addAttribute("name", principal.getFirstAttribute("fullName"));
        model.addAttribute("userName", principal.getFirstAttribute("userName"));
        model.addAttribute("email", principal.getFirstAttribute("email"));

        log.info("name: " + principal.getFirstAttribute("fullName"));
        log.info("username: " + principal.getFirstAttribute("userName"));
        log.info("email: " + principal.getFirstAttribute("email"));
        return "hello";
    }

}