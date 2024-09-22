package com.study.hello.springcloud.security6.oauth2.resource.framework.security;

import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class CustomAuthorizationFilter extends AuthorizationFilter {

    /**
     * 所有的访问都需要通过权限认证
     * 被注入到过滤器链中
     *
     * @param authorizationManager
     */
    public CustomAuthorizationFilter(AuthorizationManager<HttpServletRequest> authorizationManager) {
        super(authorizationManager);
    }

}
