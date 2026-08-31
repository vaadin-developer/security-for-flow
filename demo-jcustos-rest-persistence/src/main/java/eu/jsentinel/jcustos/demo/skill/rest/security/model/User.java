package eu.jsentinel.jcustos.demo.skill.rest.security.model;

import eu.jsentinel.jcustos.demo.skill.rest.security.roles.AuthorizationRole;

import java.util.Set;

/**
 * Authenticated subject of the application. Carries the id, a display
 * name, and the set of roles the {@link AuthorizationService} resolves
 * permissions from.
 *
 * <p>Records are framework-friendly: jCustos never mutates the
 * subject; consumers always pass a fresh instance through the
 * {@code SubjectStore}.
 *
 * <p>The compact constructor defensively copies {@code roles} via
 * {@link Set#copyOf(java.util.Collection)} so the field always holds
 * an immutable {@code ImmutableCollections.SetN} — that's the form
 * Eclipse-Store (and other off-heap serializers) can re-hydrate
 * safely. Storing an {@code EnumSet} directly would corrupt on
 * reload (the JDK's internal {@code universe} array stays
 * {@code null}).
 */
public record User(Long id, String name, Set<AuthorizationRole> roles) {
  public User {
    roles = Set.copyOf(roles);
  }
}
