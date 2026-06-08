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

import com.svenruppert.vaadin.security.audit.AuditEventStore;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.dx.bootstrap.AuditBootstrap;

import java.util.Objects;

/**
 * Real V00.73 implementation of {@link AuditBootstrap}. Records every
 * selection into the {@link AuditState} held by {@link BootstrapState};
 * {@code install()} consumes the state and wires a single
 * {@link SecurityAuditService} via {@code SecurityServiceResolver}.
 *
 * <p>Package-private; instances are created exclusively by
 * {@link AbstractSecurityBootstrap}.
 *
 * @since 00.73.00
 */
final class AuditBootstrapImpl implements AuditBootstrap {

  private final AuditState state;

  AuditBootstrapImpl(AuditState state) {
    this.state = Objects.requireNonNull(state, "state");
  }

  @Override
  public AuditBootstrap securityAuditService(SecurityAuditService service) {
    state.directService(Objects.requireNonNull(service, "service"));
    return this;
  }

  @Override
  public AuditBootstrap storeBacked(AuditEventStore store) {
    // null-store is intentionally not pre-validated here; the
    // install-time validator emits the stable code
    // audit/store-backed-without-store so the user sees the same
    // diagnostic for null AND missing-call cases.
    state.storeBackedStore(store);
    return this;
  }

  @Override
  public AuditBootstrap logging() {
    state.enableLogging();
    return this;
  }

  @Override
  public AuditBootstrap ringBuffer(int capacity) {
    // Invalid capacity is recorded as configured so the install-time
    // validator can emit audit/invalid-ring-buffer-capacity.
    state.enableRingBuffer(capacity);
    return this;
  }

  @Override
  public AuditBootstrap credentialEvents(boolean enabled) {
    state.credentialEvents(enabled);
    return this;
  }
}
