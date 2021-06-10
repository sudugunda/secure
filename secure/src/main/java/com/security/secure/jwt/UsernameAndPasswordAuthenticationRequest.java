package com.security.secure.jwt;

public class UsernameAndPasswordAuthenticationRequest {

    private String Username;
    private  String Password;

    public UsernameAndPasswordAuthenticationRequest() {
    }

    public String getUsername() {
        return Username;
    }

    public void setUsername(String username) {
        Username = username;
    }

    public String getPassword() {
        return Password;
    }

    public void setPassword(String password) {
        Password = password;
    }
}
