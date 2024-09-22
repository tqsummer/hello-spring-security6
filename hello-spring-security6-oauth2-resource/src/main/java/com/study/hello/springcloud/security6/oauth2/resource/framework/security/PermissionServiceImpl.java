package com.study.hello.springcloud.security6.oauth2.resource.framework.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;

import java.util.*;

@Service
public class PermissionServiceImpl implements PermissionService {

    private final Map<String, List<String>> permissionsMap = new HashMap<>();

    {
        permissionsMap.put("/messages2", Collections.singletonList("SCOPE_profile"));
        permissionsMap.put("/messages3", Collections.singletonList("SCOPE_message"));
        permissionsMap.put("/messages4", Collections.singletonList("ROLE_customer"));
    }

    @Override
    public List<String> getRequiredPermissions(HttpServletRequest context) {
        return permissionsMap.getOrDefault(context.getRequestURI(), Collections.emptyList());
    }

    @Override
    public void refreshPermissionCache() {
        permissionsMap.put("/messages2", Collections.singletonList("SCOPE_profile"));
        permissionsMap.put("/messages3", Collections.singletonList("SCOPE_message"));
        permissionsMap.put("/messages4", Collections.singletonList("ROLE_customer"));
    }

    @Override
    public boolean isAccessAllowed(Authentication authentication, HttpServletRequest context) {
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        List<String> requiredRoles = getRequiredPermissions(context);

        // 如果权限列表为空，则表示所有用户都可以访问
        if (requiredRoles.isEmpty()) {
            return true;
        }

        // 检查用户是否具有所需的角色
        return authorities.stream().anyMatch(auth -> requiredRoles.contains(auth.getAuthority()));
    }
}
