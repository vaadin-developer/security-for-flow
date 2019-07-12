package org.rapidpm.vaadin.security.authorization.api.roles;

import org.rapidpm.frp.model.serial.Single;

public final class RoleName
    extends Single<String> {

  public RoleName(String s) {
    super(s);
  }

  public String roleName() {
    return getT1();
  }

}
