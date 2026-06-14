package com.svenruppert.jsentinel.demo.skill.vaadin.security.bootstrap;

import com.svenruppert.jsentinel.dx.bootstrap.AuditBootstrap;
import com.svenruppert.jsentinel.dx.bootstrap.SessionBootstrap;
import com.svenruppert.jsentinel.persistence.eclipsestore.EclipseStoreJSentinelStorage;

/**
 * Persistence-layer extension. Contributes the Eclipse-Store-backed
 * {@code audit} and {@code sessions} stores to the layer-1 bootstrap
 * chain.
 *
 * <p>Registered via
 * {@code META-INF/services/com.svenruppert.jsentinel.demo.skill.vaadin.security.bootstrap.BootstrapExtension}
 * — the layer-1 {@code BootstrapBuilder} loads every registered
 * extension and applies all contributions inside a single
 * {@code .audit(...) / .sessions(...) / .credentials(...)} call,
 * so hardening (or any later layer) can stack its own contributions
 * without overwriting these.
 *
 * <p>The static initialiser eagerly opens the storage backend and
 * triggers {@link BootstrapWiring#instance()} so the bootstrap
 * token lands on stdout / the token file before the first request
 * arrives.
 */
public final class PersistenceBootstrapExtension implements BootstrapExtension {

  private static final EclipseStoreJSentinelStorage STORAGE;

  static {
    STORAGE = JSentinelStorageProvider.storage();
    BootstrapWiring.instance();
  }

  @Override
  public void contributeAudit(AuditBootstrap a) {
    a.storeBacked(STORAGE.auditEventStore()).logging();
  }

  @Override
  public void contributeSessions(SessionBootstrap s) {
    s.storeBacked(STORAGE.sessionStore());
  }

  @Override
  public int order() {
    return 10;
  }
}
