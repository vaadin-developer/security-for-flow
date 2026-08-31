package eu.jsentinel.jcustos.demo.skill.vaadin.security.roles;

/**
 * Role catalog for the application.
 *
 * <p>The role-to-permission table lives in
 * {@code MyAuthorizationService}. Add a new role here, map it to
 * permissions there, and reference it in {@code @VisibleFor(...)} on
 * views.
 */
public enum AuthorizationRole {
  ADMIN,
  USER
}
