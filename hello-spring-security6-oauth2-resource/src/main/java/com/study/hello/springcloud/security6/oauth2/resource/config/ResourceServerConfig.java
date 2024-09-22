package com.study.hello.springcloud.security6.oauth2.resource.config;

import com.study.hello.springcloud.security6.oauth2.resource.framework.security.CustomAccessDeniedHandler;
import com.study.hello.springcloud.security6.oauth2.resource.framework.security.CustomAuthenticationEntryPoint;
import com.study.hello.springcloud.security6.oauth2.resource.framework.security.CustomJwtGrantedAuthoritiesConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
public class ResourceServerConfig {

    private final CustomJwtGrantedAuthoritiesConverter customJwtGrantedAuthoritiesConverter;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    public ResourceServerConfig(CustomJwtGrantedAuthoritiesConverter customJwtGrantedAuthoritiesConverter,
                                CustomAccessDeniedHandler customAccessDeniedHandler,
                                CustomAuthenticationEntryPoint customAuthenticationEntryPoint) {
        this.customJwtGrantedAuthoritiesConverter = customJwtGrantedAuthoritiesConverter;
        this.customAccessDeniedHandler = customAccessDeniedHandler;
        this.customAuthenticationEntryPoint = customAuthenticationEntryPoint;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(customJwtGrantedAuthoritiesConverter);

        http
                // 所有的访问都需要通过身份认证
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated())
                // 配置资源服务器
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter)))

                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
                        .accessDeniedHandler(customAccessDeniedHandler))
                // 禁用 session
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // 禁用 CSRF
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

}
