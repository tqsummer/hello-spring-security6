package com.study.hello.springcloud.security6.oauth2.resource.framework.security;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

import java.util.function.Supplier;

@Component
public class CustomAuthorizationManager implements AuthorizationManager<HttpServletRequest> {

    private final PermissionService permissionService;

    public CustomAuthorizationManager(PermissionService permissionService) {
        this.permissionService = permissionService;
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, HttpServletRequest context) {

        Authentication auth = authentication.get();

        // 确保用户已认证
        if (auth == null || !auth.isAuthenticated()) {
            return new AuthorizationDecision(false);
        }

        // 检查权限逻辑
        boolean isAccessAllowed = permissionService.isAccessAllowed(auth, context);

        return new AuthorizationDecision(isAccessAllowed);
    }

}
