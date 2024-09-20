package com.study.hello.springcloud.security6.oauth2.server.framework.security.customize;

import com.study.hello.springcloud.security6.oauth2.server.framework.security.CustomAuthorizationGrantType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class PasswordLikeAuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(PasswordLikeAuthenticationProvider.class);

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<OAuth2Token> tokenGenerator;

    public PasswordLikeAuthenticationProvider(UserDetailsService userDetailsService,
                                              PasswordEncoder passwordEncoder,
                                              RegisteredClientRepository registeredClientRepository,
                                              OAuth2AuthorizationService authorizationService,
                                              OAuth2TokenGenerator<OAuth2Token> tokenGenerator) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        PasswordLikeAuthenticationToken passwordLikeAuthentication = (PasswordLikeAuthenticationToken) authentication;

        String username = passwordLikeAuthentication.getUsername();
        String password = passwordLikeAuthentication.getPassword();
        Set<String> requestedScopes = passwordLikeAuthentication.getScopes();

        UserDetails user = userDetailsService.loadUserByUsername(username);
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        RegisteredClient registeredClient = registeredClientRepository
                .findByClientId(passwordLikeAuthentication.getClientId());
        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }

        Set<String> allowedScopes = registeredClient.getScopes();
        if (requestedScopes != null) {
            for (String scope : requestedScopes) {
                if (!allowedScopes.contains(scope)) {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
                }
            }
        } else {
            requestedScopes = allowedScopes;
        }

        Authentication usernamePasswordAuthentication = new UsernamePasswordAuthenticationToken(user, null,
                user.getAuthorities());

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(usernamePasswordAuthentication)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(requestedScopes)
                .authorizationGrantType(CustomAuthorizationGrantType.PASSWORD_LIKE)
                .authorizationGrant(passwordLikeAuthentication)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN);
        ;

        OAuth2TokenContext tokenContext = tokenContextBuilder.build();

        // 添加日志记录
        logger.info("Token context: {}", tokenContext);

        OAuth2Token generatedToken = tokenGenerator.generate(tokenContext);
        OAuth2AccessToken accessToken = getoAuth2AccessToken(generatedToken, requestedScopes);

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(user.getUsername())
                .authorizationGrantType(CustomAuthorizationGrantType.PASSWORD_LIKE)
                .token(accessToken);

        OAuth2Authorization authorization = authorizationBuilder.build();
        authorizationService.save(authorization);

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("custom_parameter", "custom_value");

        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient, usernamePasswordAuthentication, accessToken, null, additionalParameters);
    }

    private static OAuth2AccessToken getoAuth2AccessToken(OAuth2Token generatedToken, Set<String> requestedScopes) {
        OAuth2AccessToken accessToken;
        if (generatedToken instanceof Jwt) {
            Jwt jwt = (Jwt) generatedToken;
            accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                    jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), requestedScopes);

            // 使用 accessToken 进行后续处理
        } else if (generatedToken instanceof OAuth2AccessToken) {
            accessToken = (OAuth2AccessToken) generatedToken;
            // 直接使用 accessToken
        } else {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR);
        }
        return accessToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PasswordLikeAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
