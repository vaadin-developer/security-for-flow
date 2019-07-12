package org.rapidpm.vaadin.security.authorization.api.permissions;

import org.rapidpm.frp.model.Single;

public final class PermissionName
    extends Single<String> {
  public PermissionName(String s) {
    super(s);
  }

  public String permissionName() {
    return getT1();
  }
}
