package com.study.hello.springcloud.security6.oauth2.framework.security;

import com.study.hello.springcloud.security6.oauth2.persistence.repository.RegisteredClientEntityRepository;
import com.study.hello.springcloud.security6.oauth2.persistence.entity.RegisteredClientEntity;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class RegisteredClientRepositoryImpl implements RegisteredClientRepository {

    private final RegisteredClientEntityRepository clientEntityRepository;

    public RegisteredClientRepositoryImpl(RegisteredClientEntityRepository clientEntityRepository) {
        this.clientEntityRepository = clientEntityRepository;
    }

    @Override
    @Transactional
    public void save(RegisteredClient registeredClient) {
        // 将 RegisteredClient 转换为 RegisteredClientEntity 并保存到数据库
        RegisteredClientEntity entity = new RegisteredClientEntity();
        entity.setClientId(registeredClient.getClientId());
        entity.setClientSecret(registeredClient.getClientSecret());
        entity.setRedirectUri(registeredClient.getRedirectUris().iterator().next()); // 假设只有一个 Redirect URI
        entity.setScopes(String.join(",", registeredClient.getScopes()));
        entity.setAuthorizationGrantTypes(
                registeredClient.getAuthorizationGrantTypes().stream()
                        .map(AuthorizationGrantType::getValue)
                        .collect(Collectors.joining(","))
        );

        clientEntityRepository.save(entity);
    }

    @Override
    public RegisteredClient findById(String id) {
        Optional<RegisteredClientEntity> clientOpt = clientEntityRepository.findById(Long.valueOf(id));
        return clientOpt.map(this::toRegisteredClient).orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Optional<RegisteredClientEntity> clientOpt = clientEntityRepository.findByClientId(clientId);

        RegisteredClient registeredClient = clientOpt.map(this::toRegisteredClient).orElse(null);
        if (registeredClient != null) {
            System.out.println("Client ID: " + registeredClient.getClientId());
            System.out.println("Authorized Grant Types: " + registeredClient.getAuthorizationGrantTypes());
            System.out.println("Redirect URIs: " + registeredClient.getRedirectUris());
            System.out.println("Scopes: " + registeredClient.getScopes());
        }
        return registeredClient;
    }

    private RegisteredClient toRegisteredClient(RegisteredClientEntity entity) {
        return RegisteredClient.withId(entity.getId().toString())
                .clientId(entity.getClientId())
                .clientSecret(entity.getClientSecret())
                .redirectUri(entity.getRedirectUri())
                .scopes(scopes -> scopes.addAll(
                        Stream.of(entity.getScopes().split(","))
                                .map(String::trim) // 去除多余的空格
                                .collect(Collectors.toSet())
                ))
                .authorizationGrantType(new AuthorizationGrantType(entity.getAuthorizationGrantTypes()))
                .build();
    }
}