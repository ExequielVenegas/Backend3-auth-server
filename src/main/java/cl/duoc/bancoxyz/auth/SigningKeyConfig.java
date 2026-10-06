package cl.duoc.bancoxyz.auth;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HexFormat;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

@Configuration(proxyBeanMethods = false)
public class SigningKeyConfig {
    @Bean
    JWKSource<SecurityContext> signingKeys(
            @Value("${auth.signing-key-store}") Resource resource,
            @Value("${auth.signing-key-password}") String password) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream input = resource.getInputStream()) {
            store.load(input, password.toCharArray());
        }
        RSAPrivateKey privateKey = (RSAPrivateKey) store.getKey("jwt", password.toCharArray());
        RSAPublicKey publicKey = (RSAPublicKey) store.getCertificate("jwt").getPublicKey();
        String kid = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded()));
        RSAKey key = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(kid).build();
        return new ImmutableJWKSet<>(new JWKSet(key));
    }
}
