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

import com.svenruppert.vaadin.security.authorization.api.roles.RoleHierarchy;

/**
 * Role sub-builder of the fluent bootstrap.
 *
 * <p><strong>V00.73 status:</strong> single-method typed surface —
 * {@link #hierarchy(RoleHierarchy)} wires
 * {@code SecurityServiceResolver.setRoleHierarchy(...)}.
 *
 * <p>V00.73 intentionally exposes only {@code hierarchy(...)} in the
 * fluent surface. The {@code RolePermissionMapping} type has no
 * resolver setter in V00.71; a {@code .mapping(...)} fluent shortcut
 * would have to either invent one (Konzept §9 rejects this) or be a
 * silent no-op. The sub-builder shape stays in place so future
 * releases can add methods without breaking the {@code .roles(...)}
 * call site.
 *
 * @since 00.72.00
 */
public interface RoleBootstrap {

  RoleBootstrap hierarchy(RoleHierarchy hierarchy);
}
