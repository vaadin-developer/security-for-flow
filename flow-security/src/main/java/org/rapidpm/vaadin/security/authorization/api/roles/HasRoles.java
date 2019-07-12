package org.rapidpm.vaadin.security.authorization.api.roles;

import java.util.stream.Stream;

public interface HasRoles {
  Stream<RoleName> roleNames();
}
