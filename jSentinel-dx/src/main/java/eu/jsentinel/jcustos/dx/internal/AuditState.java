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

import eu.jsentinel.jcustos.audit.AuditEventStore;
import eu.jsentinel.jcustos.audit.JSentinelAuditService;

/**
 * Sub-aggregate of {@link BootstrapState} holding everything the
 * {@code .audit(...)} sub-builder records during a fluent bootstrap
 * call.
 *
 * <p><strong>Internal API.</strong> Public methods exist for
 * adapter-DX modules; the type is not part of the V00.72 public
 * surface.
 *
 * @since 00.73.00
 */
public final class AuditState {

  private JSentinelAuditService directService;
  private AuditEventStore storeBackedStore;
  private boolean storeBackedRequested;
  private boolean loggingEnabled;
  private boolean ringBufferEnabled;
  private int ringBufferCapacity;
  private boolean ringBufferCapacityProvided;
  private boolean credentialEventsConfigured;
  private boolean credentialEventsEnabled;

  public JSentinelAuditService directService() {
    return directService;
  }

  public void directService(JSentinelAuditService service) {
    this.directService = service;
  }

  public AuditEventStore storeBackedStore() {
    return storeBackedStore;
  }

  public boolean storeBackedRequested() {
    return storeBackedRequested;
  }

  public void storeBackedStore(AuditEventStore store) {
    this.storeBackedStore = store;
    this.storeBackedRequested = true;
  }

  public boolean loggingEnabled() {
    return loggingEnabled;
  }

  public void enableLogging() {
    this.loggingEnabled = true;
  }

  public boolean ringBufferEnabled() {
    return ringBufferEnabled;
  }

  public int ringBufferCapacity() {
    return ringBufferCapacity;
  }

  public boolean ringBufferCapacityProvided() {
    return ringBufferCapacityProvided;
  }

  public void enableRingBuffer(int capacity) {
    this.ringBufferEnabled = true;
    this.ringBufferCapacity = capacity;
    this.ringBufferCapacityProvided = true;
  }

  public boolean credentialEventsConfigured() {
    return credentialEventsConfigured;
  }

  public boolean credentialEventsEnabled() {
    return credentialEventsEnabled;
  }

  public void credentialEvents(boolean enabled) {
    this.credentialEventsConfigured = true;
    this.credentialEventsEnabled = enabled;
  }

  /**
   * @return {@code true} when a non-direct selection method
   *         ({@code storeBacked}, {@code logging}, {@code ringBuffer})
   *         contributed to this state
   */
  public boolean hasCompositionInputs() {
    return storeBackedRequested || loggingEnabled || ringBufferEnabled;
  }

  /**
   * @return {@code true} when any selection method ran at all —
   *         {@code .audit(a -> {})} returns {@code false} here
   */
  public boolean hasAnySelection() {
    return directService != null
        || storeBackedRequested
        || loggingEnabled
        || ringBufferEnabled
        || credentialEventsConfigured;
  }
}
