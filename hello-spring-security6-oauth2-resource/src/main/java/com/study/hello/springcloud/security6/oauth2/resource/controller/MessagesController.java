package com.study.hello.springcloud.security6.oauth2.resource.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MessagesController {
    @GetMapping("/messages1")
    public String getMessages1() {
        return " hello Message 1";
    }

    @GetMapping("/messages2")
    @PreAuthorize("hasAuthority('SCOPE_profile')")
    public String getMessages2() {
        return " hello Message 2";
    }

    @GetMapping("/messages3")
    @PreAuthorize("hasAuthority('SCOPE_Message')")
    public String getMessages3() {
        return " hello Message 3";
    }

    /**
     * 自定义附加权限
     *
     * @return
     */
    @GetMapping("/messages4")
    @PreAuthorize("hasAuthority('ROLE_customer')")
    public String getMessages4() {
        return " hello Message 4 customer";
    }
}
