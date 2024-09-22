package com.study.hello.springcloud.security6.oauth2.resource.framework.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

@Component
public class CustomJwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final JwtGrantedAuthoritiesConverter defaultGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        // 获取默认的权限 (例如 SCOPE_*)
        Collection<GrantedAuthority> authorities = new HashSet<>(defaultGrantedAuthoritiesConverter.convert(jwt));

        // 从 JWT 中获取 roles 并附加到权限
        List<String> roles = jwt.getClaimAsStringList("roles");
        if (Objects.nonNull(roles)) {
            Set<SimpleGrantedAuthority> additionalAuthorities = roles.stream().distinct().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).collect(Collectors.toSet());
            authorities.addAll(additionalAuthorities);
        }

        // 添加customer角色权限
        authorities.add(new SimpleGrantedAuthority("ROLE_customer"));

        return authorities;
    }
}
