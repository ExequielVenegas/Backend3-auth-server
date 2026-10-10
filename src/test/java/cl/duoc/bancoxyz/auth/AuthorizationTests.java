package cl.duoc.bancoxyz.auth;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
    "auth.web-client-secret=only-for-tests-never-use-this-secret",
    "auth.mobile-client-secret=mobile-only-tests-never-use-this-secret",
    "auth.atm-client-secret=atm-only-tests-never-use-this-secret",
    "auth.issuer=http://localhost:9000"
})
@AutoConfigureMockMvc
class AuthorizationTests {
    static final String SECRET = "only-for-tests-never-use-this-secret";
    @Autowired MockMvc mvc;
    @MockitoBean(name = "signingKeys") JWKSource<SecurityContext> keys;
    RSAKey key;

    @BeforeEach void signingKey() throws Exception {
        key = new RSAKeyGenerator(2048).keyID("test-key").generate();
        when(keys.get(any(), any())).thenAnswer(call ->
            ((JWKSelector) call.getArgument(0)).select(new JWKSet(key)));
    }

    @Test void issuesSignedAccessTokenWithAudienceAndShortLifetime() throws Exception {
        String body = mvc.perform(post("/oauth2/token").with(httpBasic("web-demo", SECRET))
                .param("grant_type", "client_credentials").param("scope", "web.read web.write"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token_type").value("Bearer"))
            .andExpect(jsonPath("$.refresh_token").doesNotExist())
            .andReturn().getResponse().getContentAsString();
        var response = new ObjectMapper().readValue(body, Map.class);
        SignedJWT token = SignedJWT.parse((String) response.get("access_token"));
        assertTrue(token.verify(new RSASSAVerifier(key.toRSAPublicKey())));
        assertEquals("http://localhost:9000", token.getJWTClaimsSet().getIssuer());
        assertEquals(List.of("bff-web"), token.getJWTClaimsSet().getAudience());
        assertEquals("web-demo", token.getJWTClaimsSet().getSubject());
        assertTrue(token.getJWTClaimsSet().getStringListClaim("scope").contains("web.write"));
        assertEquals(300_000L, token.getJWTClaimsSet().getExpirationTime().getTime()
                - token.getJWTClaimsSet().getIssueTime().getTime());
    }

    @Test void customerScopesIncludeDomainAudience() throws Exception {
        String body = mvc.perform(post("/oauth2/token").with(httpBasic("web-demo", SECRET))
                .param("grant_type", "client_credentials")
                .param("scope", "web.customers.read web.customers.write"))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        var response = new ObjectMapper().readValue(body, Map.class);
        var claims = SignedJWT.parse((String) response.get("access_token")).getJWTClaimsSet();
        assertEquals(List.of("bff-web", "customer-service"), claims.getAudience());
        assertTrue(claims.getStringListClaim("scope").contains("web.customers.write"));
    }

    @Test void rejectsWrongSecret() throws Exception {
        mvc.perform(post("/oauth2/token").with(httpBasic("web-demo", "incorrect"))
                .param("grant_type", "client_credentials").param("scope", "web.read"))
            .andExpect(status().isUnauthorized());
    }
    @Test void channelsCannotRequestEachOthersScopes() throws Exception {
        mvc.perform(post("/oauth2/token").with(httpBasic("mobile-demo","mobile-only-tests-never-use-this-secret"))
            .param("grant_type","client_credentials").param("scope","web.payments.write"))
            .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_scope"));
        mvc.perform(post("/oauth2/token").with(httpBasic("atm-demo","atm-only-tests-never-use-this-secret"))
            .param("grant_type","client_credentials").param("scope","atm.accounts.write"))
            .andExpect(status().isBadRequest());
    }
    @Test void channelsReceiveOwnAudienceAndDomainAudiences() throws Exception {
        for(String channel:List.of("mobile","atm")) {
            String body=mvc.perform(post("/oauth2/token").with(httpBasic(channel+"-demo",channel+"-only-tests-never-use-this-secret"))
                .param("grant_type","client_credentials").param("scope",channel+".customers.read "+channel+".accounts.read "+channel+".payments.write"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
            var response=new ObjectMapper().readValue(body,Map.class);
            assertEquals(List.of("bff-"+channel,"customer-service","account-service","payment-service"),SignedJWT.parse((String)response.get("access_token")).getJWTClaimsSet().getAudience());
        }
    }
    @Test void paymentScopesHaveOnlyPaymentAudience() throws Exception {
        String body=mvc.perform(post("/oauth2/token").with(httpBasic("web-demo",SECRET))
                .param("grant_type","client_credentials").param("scope","web.payments.read web.payments.write"))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        var response=new ObjectMapper().readValue(body,Map.class);
        assertEquals(List.of("bff-web","payment-service"),SignedJWT.parse((String)response.get("access_token")).getJWTClaimsSet().getAudience());
    }
    @Test void accountWriterGetsOnlyRequiredDomainAudiences() throws Exception {
        String body=mvc.perform(post("/oauth2/token").with(httpBasic("web-demo",SECRET))
                .param("grant_type","client_credentials").param("scope","web.accounts.write"))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        var response=new ObjectMapper().readValue(body,Map.class);
        var claims=SignedJWT.parse((String)response.get("access_token")).getJWTClaimsSet();
        assertEquals(List.of("bff-web","customer-service","account-service"),claims.getAudience());
        assertEquals(List.of("web.accounts.write"),claims.getStringListClaim("scope"));
    }

    @Test void rejectsUnknownClient() throws Exception {
        mvc.perform(post("/oauth2/token").with(httpBasic("unknown", SECRET))
                .param("grant_type", "client_credentials"))
            .andExpect(status().isUnauthorized());
    }

    @Test void rejectsUnregisteredScope() throws Exception {
        mvc.perform(post("/oauth2/token").with(httpBasic("web-demo", SECRET))
                .param("grant_type", "client_credentials").param("scope", "web.admin"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("invalid_scope"));
    }

    @Test void jwksPublishesOnlyPublicKey() throws Exception {
        mvc.perform(get("/oauth2/jwks"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.keys[0].kid").value("test-key"))
            .andExpect(jsonPath("$.keys[0].n").exists())
            .andExpect(jsonPath("$.keys[0].d").doesNotExist())
            .andExpect(jsonPath("$.keys[0].p").doesNotExist());
    }
}
