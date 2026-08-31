package eu.jsentinel.jcustos.demo.skill.standalone.security.model;

/** Username/password credentials passed into the AuthenticationService. */
public record Credentials(String username, String password) {
}
