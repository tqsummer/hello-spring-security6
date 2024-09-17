package com.study.hello.springcloud.security6.oauth2.resource.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
public class ResourceServerConfig {

    private final CustomJwtGrantedAuthoritiesConverter customJwtGrantedAuthoritiesConverter;

    public ResourceServerConfig(CustomJwtGrantedAuthoritiesConverter customJwtGrantedAuthoritiesConverter) {
        this.customJwtGrantedAuthoritiesConverter = customJwtGrantedAuthoritiesConverter;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(customJwtGrantedAuthoritiesConverter);
        
        http.authorizeHttpRequests((authorizeHttpRequests) -> authorizeHttpRequests
                        //所有的访问都需要通过身份认证
                        .anyRequest().authenticated()
                )
//                .oauth2ResourceServer((oauth2ResourceServer) -> oauth2ResourceServer
//                        .jwt(Customizer.withDefaults())
//
//                );

                .oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
                );

        return http.build();
    }

}
