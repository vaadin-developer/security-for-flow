package eu.jsentinel.jcustos.demo.skill.standalone.security.model;

import eu.jsentinel.jcustos.demo.skill.standalone.security.roles.AuthorizationRole;

import java.util.Set;

/**
 * Authenticated subject of the application. Carries the id, a display
 * name, and the set of roles the {@link AuthorizationService} resolves
 * permissions from.
 *
 * <p>Records are framework-friendly: jSentinel never mutates the
 * subject; consumers always pass a fresh instance through the
 * {@code SubjectStore}.
 */
public record User(Long id, String name, Set<AuthorizationRole> roles) {
}
