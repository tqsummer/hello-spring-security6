package com.study.hello.springcloud.security.config;

import com.study.hello.springcloud.security.handler.BussinessAccessDeniedHandler;
import com.study.hello.springcloud.security.handler.LoginFailureHandler;
import com.study.hello.springcloud.security.handler.LoginSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

//@Configuration
//@EnableWebSecurity
public class SecurityConfig2 {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {


        //前后端分离认证逻辑
        http.formLogin((formLogin) -> formLogin
                .loginProcessingUrl("/login") //登录访问接口
                .successHandler(new LoginSuccessHandler()) //登录成功处理逻辑
                .failureHandler(new LoginFailureHandler()) //登录失败处理逻辑
        );

        //对请求进行访问控制设置
        http.authorizeHttpRequests((authorizeHttpRequests) -> authorizeHttpRequests
                //设置哪些路径可以直接访问，不需要认证
                .requestMatchers("/login").permitAll()  //不需要认证
                .requestMatchers("/index").hasRole("user")  //需要user角色,底层会判断是否有ROLE_admin权限
                .requestMatchers("/index2").hasRole("admin")
                .requestMatchers("/user/**").hasAuthority("user:api") //需要user:api权限
                .requestMatchers("/order/**").hasAuthority("order:api")
                .anyRequest().authenticated()  //其他路径的请求都需要认证
        );

        //关闭跨站点请求伪造csrf防护
        http.csrf((csrf) -> csrf.disable());
        //访问受限后的异常处理
        http.exceptionHandling((exceptionHandling) ->
                exceptionHandling.accessDeniedHandler(new BussinessAccessDeniedHandler())
        );
        return http.build();

    }


    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("fxq")
                .password("123456")
                .roles("user")
                .build();

        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("123456")
                // 注意： roles和authorities不能同时配置，同时配置后者会覆盖前者的权限
                .authorities("ROLE_admin", "ROLE_user", "user:api", "order:api")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }


}