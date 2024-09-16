package com.study.hello.springcloud.security6.oauth2.server.framework.security;

import com.study.hello.springcloud.security6.oauth2.server.persistence.entity.OAuth2UserEntity;
import com.study.hello.springcloud.security6.oauth2.server.persistence.repository.OAuth2UserEntityRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.stream.Collectors;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final OAuth2UserEntityRepository oauth2UserRepository;

    public UserDetailsServiceImpl(OAuth2UserEntityRepository oauth2UserRepository) {
        this.oauth2UserRepository = oauth2UserRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        OAuth2UserEntity user = oauth2UserRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                Arrays.stream(user.getRoles().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList())
        );
    }
}
