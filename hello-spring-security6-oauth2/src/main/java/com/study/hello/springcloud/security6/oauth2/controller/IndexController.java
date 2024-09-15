package com.study.hello.springcloud.security6.oauth2.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @GetMapping("/login2")
    public String login() {
        return "login page";
    }


}
