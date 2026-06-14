package com.svenruppert.jsentinel.demo.skill.standalone.security.model;

/** Username/password credentials passed into the AuthenticationService. */
public record Credentials(String username, String password) {
}
