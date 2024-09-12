package com.study.hello.springcloud.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity  //开启spring sercurity支持
public class SecurityConfig {


    /**
     * 配置用户信息
     *
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService() {
        //使用默认加密方式bcrypt对密码进行加密，添加用户信息
        //加密方式1：{id}encodedPassword ，id为加密算法类型
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("fxq")
                .password("123456")
                .roles("user")
                .build();

        System.out.println(user.getPassword());

        UserDetails admin = User.withUsername("admin")
                .password("{noop}123456") //noop表示对密码不加密
                .roles("admin", "user")
                .build();
        System.out.println(admin.getPassword());

        // 加密方式2： passwordEncoder().encode("123456")
//        String userEncoderPass = passwordEncoder().encode("123456");
//        UserDetails user = User
//                .withUsername("fxq")
//                .password(userEncoderPass)
//                .roles("user")
//                .build();
//        System.out.println(userEncoderPass);
//        System.out.println(user.getPassword());
//        UserDetails admin = User.withUsername("admin")
//                //指定加密算法对密码加密
//                .password(passwordEncoder().encode("123456"))
//                .roles("admin", "user")
//                .build();
        return new InMemoryUserDetailsManager(user, admin);
    }

//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        //return NoOpPasswordEncoder.getInstance();  //不加密
//        return new BCryptPasswordEncoder();  //加密方式bcrypt
//    }


}
