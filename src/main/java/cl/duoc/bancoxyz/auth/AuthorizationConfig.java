package cl.duoc.bancoxyz.auth;

import java.time.Duration;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.settings.*;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@Configuration(proxyBeanMethods = false)
public class AuthorizationConfig {
    @Bean
    @Order(1)
    SecurityFilterChain authorizationEndpoints(HttpSecurity http) throws Exception {
        http.oauth2AuthorizationServer(server ->
                http.securityMatcher(server.getEndpointsMatcher()))
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain otherEndpoints(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health").permitAll()
                .anyRequest().denyAll())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(ex -> ex.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
        return http.build();
    }

    @Bean
    RegisteredClientRepository clients(@Value("${auth.web-client-secret}") String secret) {
        if (secret.length() < 32) {
            throw new IllegalArgumentException("AUTH_WEB_CLIENT_SECRET debe tener al menos 32 caracteres");
        }
        RegisteredClient web = RegisteredClient.withId("web-demo")
            .clientId("web-demo")
            .clientSecret(PasswordEncoderFactories.createDelegatingPasswordEncoder().encode(secret))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("web.read")
            .scope("web.info")
            .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(5)).build())
            .build();
        return new InMemoryRegisteredClientRepository(web);
    }

    @Bean
    AuthorizationServerSettings serverSettings(@Value("${auth.issuer}") String issuer) {
        return AuthorizationServerSettings.builder().issuer(issuer).build();
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> audience() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getClaims().audience(List.of("bff-web"));
            }
        };
    }
}
