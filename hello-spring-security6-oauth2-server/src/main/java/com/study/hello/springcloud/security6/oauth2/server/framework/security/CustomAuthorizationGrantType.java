package com.study.hello.springcloud.security6.oauth2.server.framework.security;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

public class CustomAuthorizationGrantType {
    public static final AuthorizationGrantType PASSWORD_LIKE = new AuthorizationGrantType("password_like");
}

