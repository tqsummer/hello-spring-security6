package com.study.hello.springcloud.security6.oauth2.server.persistence.repository;

import com.study.hello.springcloud.security6.oauth2.server.persistence.entity.OAuth2UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface OAuth2UserEntityRepository extends JpaRepository<OAuth2UserEntity, Long> {
    Optional<OAuth2UserEntity> findByUsername(String username);
}
