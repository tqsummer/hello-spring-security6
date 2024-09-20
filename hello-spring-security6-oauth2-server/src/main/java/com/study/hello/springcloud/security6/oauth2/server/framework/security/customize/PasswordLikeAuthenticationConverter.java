package com.study.hello.springcloud.security6.oauth2.server.framework.security.customize;


import com.study.hello.springcloud.security6.oauth2.server.framework.security.CustomAuthorizationGrantType;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class PasswordLikeAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!CustomAuthorizationGrantType.PASSWORD_LIKE.getValue().equals(grantType)) {
            return null;
        }

        String username = request.getParameter(OAuth2ParameterNames.USERNAME);
        String password = request.getParameter(OAuth2ParameterNames.PASSWORD);

        if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_request"));
        }

        Set<String> requestedScopes = null;
        String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
        if (StringUtils.hasText(scope)) {
            requestedScopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        }

        // 从 Authorization 头中提取 client_id 和 client_secret
        String clientId = null;
        String clientSecret = null;
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Basic ")) {
            String base64Credentials = authorizationHeader.substring(6);
            String credentials = new String(Base64.getDecoder().decode(base64Credentials), StandardCharsets.UTF_8);
            String[] values = credentials.split(":", 2);
            clientId = values[0];
            clientSecret = values[1];
        }

        if (!StringUtils.hasText(clientId) || !StringUtils.hasText(clientSecret)) {
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_request", "Client ID and secret must be provided", null));
        }

        // 获取 clientPrincipal
        Authentication clientPrincipal = (Authentication) request.getUserPrincipal();

        if (clientPrincipal == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_request", "Client principal must be provided", null));
        }

        Map<String, Object> additionalParameters = request.getParameterMap().entrySet().stream()
                .filter(e -> !e.getKey().equals(OAuth2ParameterNames.GRANT_TYPE)
                        && !e.getKey().equals(OAuth2ParameterNames.USERNAME)
                        && !e.getKey().equals(OAuth2ParameterNames.PASSWORD)
                        && !e.getKey().equals(OAuth2ParameterNames.SCOPE))
                .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue()[0]));

        return new PasswordLikeAuthenticationToken(clientPrincipal, username, password, clientId, requestedScopes, additionalParameters);
    }
}
