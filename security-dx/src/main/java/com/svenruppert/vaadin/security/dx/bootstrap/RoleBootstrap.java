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
package com.svenruppert.vaadin.security.dx.bootstrap;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleHierarchy;

/**
 * Role sub-builder of the V00.72 fluent bootstrap.
 * <p>
 * <strong>V00.72 status:</strong> the call is <em>recorded only</em>;
 * no {@code RoleHierarchy} wiring into {@code SecurityServiceResolver}
 * is applied. Real hierarchy binding is staged for V00.73; the
 * hierarchy still works in V00.72 when registered through the existing
 * SPI / `META-INF/services` path.
 *
 * @since 00.72.00
 */
@ExperimentalSecurityApi
public interface RoleBootstrap {

  RoleBootstrap hierarchy(RoleHierarchy hierarchy);
}
