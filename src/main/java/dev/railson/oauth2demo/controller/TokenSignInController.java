package dev.railson.oauth2demo.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.*;
import dev.railson.oauth2demo.utils.JwtUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.OffsetDateTime;
import java.util.*;

@Controller
@RequestMapping("/tokensignin")
public class TokenSignInController {
    private Map<String, String> providerNames = new HashMap<>() {{
            put("https://accounts.google.com", "Google");
        }};
    @Value(value = "${oauth.google.clientId}")
    private String validAudience;
    @Value(value = "${jwt.issuer}")
    private String jwtIssuer;
    @Value(value = "${jwt.key}")
    private String jwtKey;

    @PostMapping
    public String tokenSignIn(@RequestParam String idToken,  Model model) throws JOSEException, IOException, ParseException {
        var claims = JwtUtils.validateIdToken(idToken, Collections.singleton(validAudience));
        if(claims == null){
            model.addAttribute("idToken validation failed");
            return "error";
        }
        var userId = simulateUserCreationOrRetrieving(claims.get("sub").toString());
        var idTokenIssuer = claims.get("iss").toString();
        var iat = OffsetDateTime.now().toEpochSecond();
        var exp = iat + 60 * 10; // Sum 10 minutes
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode payload = mapper.createObjectNode();
        payload.put("iss",jwtIssuer);
        payload.put("sub",userId);
        payload.put("amr","external");
        payload.put("idp",providerNames.getOrDefault(idTokenIssuer,idTokenIssuer));
        payload.put("iat", iat);
        payload.put("exp",exp);

        // We need a 256-bit key for HS256 which must be pre-shared
        byte[] sharedKey = jwtKey.getBytes(StandardCharsets.UTF_8);

        var jws = JwtUtils.generateJws(payload.toString(), sharedKey);

        model.addAttribute("accessToken", jws.serialize());
        return "demo";
    }


    private String simulateUserCreationOrRetrieving(String sub) {
        Random random = new Random(sub.hashCode());
        String seed = String.valueOf(random.nextInt(5));
        return UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8)).toString();
    }
}
