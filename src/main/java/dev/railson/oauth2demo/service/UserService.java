package dev.railson.oauth2demo.service;

import dev.railson.oauth2demo.model.User;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    private List<User> users = List.of(new User[]{
            new User(0, "Crash", "Bandicoot", "https://i.imgur.com/pNN0Ftb.png"),
            new User(1, "Coco", "Bandicoot", "https://i.imgur.com/FQJ91Hr.jpg"),
            new User(2, "Crunch", "Bandicoot", "https://i.imgur.com/nNbTaQL.jpg"),
            new User(3, "Neo", "Cortex", "https://i.imgur.com/pf8UyXW.png"),
            new User(4, "Nina", "Cortex", "https://i.imgur.com/iyKXUUH.jpg")
    });

    public User getUser(String userId){

        var foundUser = users.stream().filter(user -> user.getUuid().equals(userId)).findFirst();

        if (foundUser.isEmpty()) {
            return null;
        }

        return foundUser.get();

    }
}
