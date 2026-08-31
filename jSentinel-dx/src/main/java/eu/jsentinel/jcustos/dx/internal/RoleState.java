/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.internal;

import eu.jsentinel.jcustos.authorization.api.roles.RoleHierarchy;

/**
 * Sub-aggregate of {@link BootstrapState} holding the role
 * configuration accumulated by {@code .roles(...)}.
 *
 * @since 00.73.00
 */
public final class RoleState {

  private RoleHierarchy hierarchy;

  public RoleHierarchy hierarchy() {
    return hierarchy;
  }

  public void hierarchy(RoleHierarchy hierarchy) {
    this.hierarchy = hierarchy;
  }
}
