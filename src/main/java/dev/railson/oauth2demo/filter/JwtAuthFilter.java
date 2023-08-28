package dev.railson.oauth2demo.filter;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import dev.railson.oauth2demo.model.User;
import dev.railson.oauth2demo.service.UserService;
import dev.railson.oauth2demo.utils.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;

// Source: https://medium.com/javarevisited/spring-security-role-based-access-implementation-with-spring-boot-3-0-and-jwt-34164bd593fd
@Component
public class JwtAuthFilter  extends OncePerRequestFilter {
    @Value(value = "${jwt.issuer}")
    private String jwtIssuer;
    @Value(value = "${jwt.key}")
    private String jwtKey;
    private final UserService userService;


    public JwtAuthFilter(UserService userService) {
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        if(authHeader!=null && authHeader.startsWith("Bearer ")){
            String token = authHeader.substring(7);
            try {
                var claims = JwtUtils.validateAccessToken(token, jwtIssuer, jwtKey.getBytes(StandardCharsets.UTF_8));
                if(claims != null){
                    User user = userService.getUser(claims.get("sub").toString());
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user,claims, new ArrayList<>());
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            } catch (JOSEException | ParseException | BadJOSEException e) {
                throw new RuntimeException(e);
            }
        }
        filterChain.doFilter(request,response);
    }
}
