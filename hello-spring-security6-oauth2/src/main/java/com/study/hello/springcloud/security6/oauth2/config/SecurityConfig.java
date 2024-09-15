package com.study.hello.springcloud.security6.oauth2.config;

import com.study.hello.springcloud.security6.oauth2.framework.security.CustomAccessDeniedHandler;
import com.study.hello.springcloud.security6.oauth2.framework.security.CustomAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable).
                formLogin(form -> form
                        //.loginPage("/login") // 设置自定义登录页面:可以指定前端地址（全路径带http或https），也可以指向controller地址
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/home", true) // 登录成功后的跳转路径
                        .failureUrl("/login?error=true") // 登录失败后的跳转路径
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout") // 设置注销路径
                        .logoutSuccessUrl("/login?logout=true") // 注销成功后的跳转路径
                        .permitAll()
                )
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/error", "/oauth2/**", "/.well-known/jwks.json").permitAll()
                                .anyRequest().authenticated()
                )
                .exceptionHandling((exceptionHandling) ->
                        exceptionHandling
                                .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
                                .accessDeniedHandler(new CustomAccessDeniedHandler())
                );
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        // 使用 AuthenticationManagerBuilder 显式配置 UserDetailsService 和 PasswordEncoder
        AuthenticationManagerBuilder auth = http.getSharedObject(AuthenticationManagerBuilder.class);
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
        return auth.build();
    }
}
