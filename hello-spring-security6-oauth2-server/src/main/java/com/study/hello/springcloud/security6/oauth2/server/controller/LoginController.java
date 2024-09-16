package com.study.hello.springcloud.security6.oauth2.server.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping("/login.html")
    public String loginPage(HttpServletRequest request, Model model) {
        return "login"; // 确保返回的视图名与 Thymeleaf 模板匹配
    }

    @GetMapping("/logout.html")
    public String logoutPage() {
        return "logout";
    }

}
