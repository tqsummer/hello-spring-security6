package com.study.hello.springcloud.security6.oauth2.resource.framework.security;

import org.springframework.security.core.Authentication;

import jakarta.servlet.http.HttpServletRequest;

import java.util.List;

public interface PermissionService {
    /**
     * 获取给定请求上下文所需的权限列表
     *
     * @param context 请求授权上下文
     * @return 所需权限的列表
     */
    List<String> getRequiredPermissions(HttpServletRequest context);

    /**
     * 从数据源重新加载所有权限配置
     */
    void refreshPermissionCache();

    /**
     * 检查给定的认证是否有权限访问指定的请求上下文
     *
     * @param authentication 用户的认证信息
     * @param context 请求授权上下文
     * @return 如果有访问权限则返回true，否则返回false
     */
    boolean isAccessAllowed(Authentication authentication, HttpServletRequest context);
}

