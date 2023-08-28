package dev.railson.oauth2demo.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/google")
public class GoogleController {
    private final URI issuer = URI.create("https://accounts.google.com");

    @Value("${oauth.google.clientId}")
    private String clientId;
    @Value("${oauth.google.clientSecret}")
    private String clientSecret;
    @Value(value = "${oauth.google.redirectUrl}")
    private String redirectUrl;
    private final String redirectPath = "/google/callback";


    /// https://openid.net/specs/openid-connect-discovery-1_0.html
    private URI getOpenIdConfigurationUri() {
        return issuer.resolve("/.well-known/openid-configuration");
    }

    private JsonNode getOpenIdConfiguration() throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readTree(getOpenIdConfigurationUri().toURL());
    }

    private String buildRedirectUrl(String host) {
        if(redirectUrl!=null && !redirectUrl.isEmpty()){
            return redirectUrl;
        }
        // Build redirect url (It could be static since it should be registered on Google Cloud)
        if (host.contains("localhost")) {
            return "http://" + host + redirectPath;
        }
        return "https://" + host + redirectPath;
    }

    private String getSignInLocation(@RequestHeader(HttpHeaders.HOST) String host) throws IOException {
        // Get authorization endpoint
        JsonNode openIdConfiguration = getOpenIdConfiguration();
        JsonNode authorizationEndpoint = openIdConfiguration.get("authorization_endpoint");


        // Build the authorization url
        String location = authorizationEndpoint.asText() +
                "?response_type=code" +
                "&client_id=" + clientId +
                "&redirect_uri=" + buildRedirectUrl(host) +
                "&scope=openid";

        return location;
    }

    @GetMapping(value = "/sign-in", produces = "text/html")
    public ResponseEntity<String> signInHtml(@RequestHeader(HttpHeaders.HOST) String host) throws IOException {
        return ResponseEntity.ok("<html><head><meta http-equiv=\"refresh\" content=\"0; URL='" + getSignInLocation(host) + "'\"/></head></html>");
    }

    @PostMapping(value = "/sign-in", produces = "application/json")
    public ResponseEntity<String> signInJson(@RequestHeader(HttpHeaders.HOST) String host) throws IOException {
        return ResponseEntity.ok("{\"url\": \"" + getSignInLocation(host) + "\"}");
    }

    @GetMapping(value = "/callback", produces = "application/json")
    public String callback(@RequestHeader(HttpHeaders.HOST) String host, @RequestParam() String code, Model model) throws IOException {
        // Fix misdecoding on AWS Lambda
        code = java.net.URLDecoder.decode(code, StandardCharsets.UTF_8.name());

        // Get the token endpoint
        JsonNode openIdConfiguration = getOpenIdConfiguration();
        JsonNode tokenEndpoint = openIdConfiguration.get("token_endpoint");

        // Build post request
        Map<String, String> parameters = new HashMap<>();
        parameters.put("client_id", clientId);
        parameters.put("client_secret", clientSecret);
        parameters.put("grant_type", "authorization_code");
        parameters.put("code", code);
        parameters.put("redirect_uri", buildRedirectUrl(host));

        String form = parameters.entrySet()
                .stream()
                .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));

        byte[] postData = form.getBytes(StandardCharsets.UTF_8);
        int postDataLength = postData.length;

        HttpsURLConnection connection = (HttpsURLConnection) URI.create(tokenEndpoint.asText()).toURL().openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        connection.setRequestProperty("charset", "utf-8");
        connection.setRequestProperty("Content-Length", Integer.toString(postDataLength));
        connection.setUseCaches(false);


        // Send post request
        try (DataOutputStream wr = new DataOutputStream(connection.getOutputStream())) {
            wr.write(postData);
        }
        BufferedReader br = null;
        var statusCode = connection.getResponseCode();
        if (statusCode == 200) {
            br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        } else {
            br = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
        }
        StringBuilder responseBody = new StringBuilder();
        String strCurrentLine;
        while ((strCurrentLine = br.readLine()) != null) {
            responseBody.append(strCurrentLine).append("\n");
        }
        // Set variables and return the page
        if (statusCode == 200) {
            ObjectMapper mapper = new ObjectMapper();
            model.addAttribute("idToken", mapper.readTree(responseBody.toString()).get("id_token").asText());
            return "demo";
        } else {
            model.addAttribute("error", responseBody);
            return "error";
        }
    }

}
