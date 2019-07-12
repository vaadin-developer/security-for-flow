package org.rapidpm.vaadin.security.authorization.api;

import org.rapidpm.vaadin.security.authorization.api.permissions.HasPermissions;
import org.rapidpm.vaadin.security.authorization.api.roles.HasRoles;

/**
 * @param <U> the User class
 */
public interface AuthorizationService<U> {
  HasRoles rolesFor(U subject);

  HasPermissions permissionsFor(U subject);
}
