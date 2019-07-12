package org.rapidpm.vaadin.security.authorization.api.permissions;

import java.util.stream.Stream;

public interface HasPermissions {
  Stream<PermissionName> permissionNames();
}
