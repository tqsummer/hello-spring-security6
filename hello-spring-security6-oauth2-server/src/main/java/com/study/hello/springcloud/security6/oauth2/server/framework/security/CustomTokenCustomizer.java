package com.study.hello.springcloud.security6.oauth2.server.framework.security;

import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

@Component
public class CustomTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        // 添加自定义声明
        context.getClaims().claim("custom_claim", "custom_value");
        
        // 您可以根据不同的授权类型添加不同的声明
        if (context.getAuthorizationGrantType().getValue().equals("authorization_code")) {
            context.getClaims().claim("grant_type", "authorization_code");
        } else if (context.getAuthorizationGrantType().getValue().equals("client_credentials")) {
            context.getClaims().claim("grant_type", "client_credentials");
        }
        
        // 您还可以根据认证的用户信息添加声明
        if (context.getPrincipal() != null && context.getPrincipal().getPrincipal() != null) {
            context.getClaims().claim("username", context.getPrincipal().getName());
        }
    }
}
