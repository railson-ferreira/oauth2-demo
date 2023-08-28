package dev.railson.oauth2demo.controller;

import dev.railson.oauth2demo.model.User;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/me")
public class MeController {
    @GetMapping
    public ResponseEntity<Object> getMe() {
        var user = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        if (user instanceof User) {
            return ResponseEntity.ok(user);
        }
        return ResponseEntity.status(409).body("Could not found authorized user");
    }
}
