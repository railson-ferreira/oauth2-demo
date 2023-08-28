package dev.railson.oauth2demo.model;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

public class User {
    private String uuid;
    private String givenName;
    private String familyName;
    private String picture;

    public User(int sequence, String givenName, String familyName, String picture) {
        this.uuid = UUID.nameUUIDFromBytes(String.valueOf(sequence).getBytes(StandardCharsets.UTF_8)).toString();
        this.givenName = givenName;
        this.familyName = familyName;
        this.picture = picture;
    }

    public String getUuid(){
        return uuid;
    }

    public String getGivenName() {
        return givenName;
    }

    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public void setFamilyName(String familyName) {
        this.familyName = familyName;
    }

    public String getPicture() {
        return picture;
    }

    public void setPicture(String picture) {
        this.picture = picture;
    }
}
