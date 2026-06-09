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
package com.svenruppert.vaadin.security.dx.internal;

import com.svenruppert.vaadin.security.authorization.api.roles.RoleHierarchy;
import com.svenruppert.vaadin.security.dx.bootstrap.RoleBootstrap;

import java.util.Objects;

/**
 * Real V00.73 implementation of {@link RoleBootstrap}. Stores the
 * configured hierarchy in {@link RoleState}; install-time wiring
 * happens in {@code AbstractJSentinelBootstrap.applyRoleConfiguration}.
 *
 * @since 00.73.00
 */
final class RoleBootstrapImpl implements RoleBootstrap {

  private final RoleState state;

  RoleBootstrapImpl(RoleState state) {
    this.state = Objects.requireNonNull(state, "state");
  }

  @Override
  public RoleBootstrap hierarchy(RoleHierarchy hierarchy) {
    state.hierarchy(Objects.requireNonNull(hierarchy, "hierarchy"));
    return this;
  }
}
