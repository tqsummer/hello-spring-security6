package com.study.hello.springcloud.security6.oauth2.server.persistence.repository;

import com.study.hello.springcloud.security6.oauth2.server.persistence.entity.RegisteredClientEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RegisteredClientEntityRepository extends JpaRepository<RegisteredClientEntity, Long> {
    Optional<RegisteredClientEntity> findByClientId(String clientId);
}
