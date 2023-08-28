package dev.railson.oauth2demo.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.proc.*;

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class JwtUtils {

    private static String getJwksUriFromIssuer(String issuer) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        var openIdConfig = mapper.readTree(new URL(issuer + "/.well-known/openid-configuration"));
        return openIdConfig.get("jwks_uri").asText();
    }

    public static Map<String, Object> validateIdToken(String idToken, Set<String> validAudiences) throws IOException, ParseException {
        // Source: https://connect2id.com/products/nimbus-jose-jwt/examples/validating-jwt-access-tokens
        // Create a JWT processor for the access tokens
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

        // Get jwksUri
        var jwsObject = JWSObject.parse(idToken);
        var issuer = jwsObject.getPayload().toJSONObject().get("iss").toString();
        var jwksUri = getJwksUriFromIssuer(issuer);

        // The public RSA keys to validate the signatures will be sourced from the
        // OAuth 2.0 server's JWK set URL. The key source will cache the retrieved
        // keys for 5 minutes. 30 seconds prior to the cache's expiration the JWK
        // set will be refreshed from the URL on a separate dedicated thread.
        // Retrial is added to mitigate transient network errors.
        JWKSource<SecurityContext> keySource = JWKSourceBuilder
                .create(new URL(jwksUri))
                .retrying(true)
                .build();

        // The expected JWS algorithm of the access tokens (agreed out-of-band)
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

        // Configure the JWT processor with a key selector to feed matching public
        // RSA keys sourced from the JWK set URL
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(
                expectedJWSAlg,
                keySource);
        jwtProcessor.setJWSKeySelector(keySelector);

        // Set the required JWT claims for access tokens
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                validAudiences,
                new JWTClaimsSet.Builder().issuer(issuer).build(),
                new HashSet<>(),
                null
        ));

        // Process the token
        SecurityContext ctx = null; // optional context parameter, not required here
        JWTClaimsSet claimsSet;
        try {
            claimsSet = jwtProcessor.process(idToken, ctx);
        } catch (ParseException | BadJOSEException e) {
            // Invalid token
            System.err.println(e.getMessage());
            return null;
        } catch (JOSEException e) {
            // Key sourcing failed or another internal exception
            System.err.println(e.getMessage());
            return null;
        }

        // return  the token claims set
        return claimsSet.toJSONObject();
    }

    public static JWSObject generateJws(String payload, byte[] sharedKey) throws JOSEException {
        // Source: https://connect2id.com/products/nimbus-jose-jwt
        // Create an HMAC-protected JWS object with a string payload
        JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload(payload));


        // Apply the HMAC to the JWS object
        jwsObject.sign(new MACSigner(sharedKey));

        // Output in URL-safe format
        return jwsObject;
    }

    public static Map<String, Object> validateAccessToken(String accessToken, String issuer, byte[] sharedKey) throws JOSEException, ParseException, BadJOSEException {
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

        // The expected JWE algorithm and method
        JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;

        // The JWE key source
        JWKSource jweKeySource = new ImmutableSecret(sharedKey);

        // Configure a key selector to handle the decryption phase
        JWSKeySelector jwsKeySelector = new JWSVerificationKeySelector(jwsAlgorithm, jweKeySource);

        jwtProcessor.setJWSKeySelector(jwsKeySelector);

        // Set the required JWT claims for access tokens
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                new JWTClaimsSet.Builder().issuer(issuer).build(),
                new HashSet<>()
        ));


        try{
            return jwtProcessor.process(accessToken, null).toJSONObject();
        }catch (BadJWTException e){
            return null;
        }
    }
}
