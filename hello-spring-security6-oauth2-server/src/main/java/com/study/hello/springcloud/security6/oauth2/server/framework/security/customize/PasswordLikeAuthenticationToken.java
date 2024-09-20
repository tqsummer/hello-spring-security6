package com.study.hello.springcloud.security6.oauth2.server.framework.security.customize;

import com.study.hello.springcloud.security6.oauth2.server.framework.security.CustomAuthorizationGrantType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;
import java.util.Set;

public class PasswordLikeAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private final String username;
    private final String password;
    private final Set<String> scopes;
    private final String clientId;

    public PasswordLikeAuthenticationToken(Authentication clientPrincipal, String username, String password, String clientId, Set<String> scopes,
                                           Map<String, Object> additionalParameters) {
        super(CustomAuthorizationGrantType.PASSWORD_LIKE, clientPrincipal, additionalParameters);
        this.username = username;
        this.password = password;
        this.clientId = clientId;
        this.scopes = scopes;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public String getClientId() {
        return clientId;
    }
}
