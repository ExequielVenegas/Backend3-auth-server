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
    RegisteredClientRepository clients(@Value("${auth.web-client-secret}") String secret,
            @Value("${auth.mobile-client-secret}") String mobileSecret,
            @Value("${auth.atm-client-secret}") String atmSecret) {
        if (secret.length() < 32) {
            throw new IllegalArgumentException("AUTH_WEB_CLIENT_SECRET debe tener al menos 32 caracteres");
        }
        RegisteredClient web = RegisteredClient.withId("web-demo")
            .clientId("web-demo")
            .clientSecret(PasswordEncoderFactories.createDelegatingPasswordEncoder().encode(secret))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("web.read")
            .scope("web.write")
            .scope("web.info")
            .scope("web.customers.read")
            .scope("web.customers.write")
            .scope("web.accounts.read")
            .scope("web.accounts.write")
            .scope("web.accounts.import")
            .scope("web.payments.read")
            .scope("web.payments.write")
            .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(5)).build())
            .build();
        return new InMemoryRegisteredClientRepository(web,
                channelClient("mobile",mobileSecret,List.of("read","info","customers.read","accounts.read","accounts.write","payments.read","payments.write")),
                channelClient("atm",atmSecret,List.of("read","info","customers.read","accounts.read","payments.read","payments.write")));
    }

    private RegisteredClient channelClient(String channel,String secret,List<String> scopes) {
        if(secret.length()<32) throw new IllegalArgumentException("El secreto de "+channel+" requiere al menos 32 caracteres");
        var client=RegisteredClient.withId(channel+"-demo").clientId(channel+"-demo")
            .clientSecret(PasswordEncoderFactories.createDelegatingPasswordEncoder().encode(secret))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(5)).build());
        scopes.forEach(scope->client.scope(channel+"."+scope));
        return client.build();
    }

    @Bean
    AuthorizationServerSettings serverSettings(@Value("${auth.issuer}") String issuer) {
        return AuthorizationServerSettings.builder().issuer(issuer).build();
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> audience() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                String channel=context.getRegisteredClient().getClientId().replace("-demo","");
                boolean customers = context.getAuthorizedScopes().stream().anyMatch(scope -> scope.startsWith(channel+".customers."));
                var audiences = new java.util.ArrayList<>(List.of("bff-"+channel));
                boolean accounts = context.getAuthorizedScopes().stream().anyMatch(scope -> scope.startsWith(channel+".accounts."));
                if (customers || context.getAuthorizedScopes().contains(channel+".accounts.write") || context.getAuthorizedScopes().contains("web.accounts.import")) audiences.add("customer-service");
                if (accounts) audiences.add("account-service");
                if (context.getAuthorizedScopes().stream().anyMatch(scope -> scope.startsWith(channel+".payments."))) audiences.add("payment-service");
                context.getClaims().audience(audiences);
            }
        };
    }
}

