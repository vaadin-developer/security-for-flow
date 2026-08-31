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
package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.audit.AuditEventStore;
import eu.jsentinel.jcustos.audit.JSentinelAuditService;

/**
 * Audit sub-builder of the fluent bootstrap.
 *
 * <p><strong>V00.73 status:</strong> typed surface — every selection
 * method maps to a real {@link JSentinelAuditService} that is wired
 * into {@code JSentinelServiceResolver.setJSentinelAuditService(...)}
 * by {@code install()}.
 *
 * <h2>Composition rules</h2>
 * <ul>
 *   <li>{@code .securityAuditService(svc)} — registers {@code svc}
 *       directly; mixing it with any other selection in the same
 *       lambda yields {@code audit/conflicting-direct-service}.</li>
 *   <li>{@code .storeBacked(store)} — installs a
 *       {@code StoreBackedJSentinelAuditService(store)}.</li>
 *   <li>{@code .logging()} / {@code .ringBuffer(n)} — contribute
 *       sinks. A sinks-only setup builds a small DX-internal
 *       sink-forwarding service; combined with {@code .storeBacked(...)}
 *       the bootstrap tees both via a package-private
 *       {@code TeeingJSentinelAuditService}.</li>
 * </ul>
 *
 * @since 00.72.00
 */
public interface AuditBootstrap {

  /**
   * Registers an already-constructed {@link JSentinelAuditService}.
   * Must not be combined with any other selection method on the same
   * builder; doing so produces the {@code audit/conflicting-direct-service}
   * diagnostic.
   */
  AuditBootstrap securityAuditService(JSentinelAuditService service);

  /** Backs the audit pipeline by a {@link AuditEventStore}-based service. */
  AuditBootstrap storeBacked(AuditEventStore store);

  /** Adds a {@code LoggingAuditSink}. */
  AuditBootstrap logging();

  /** Adds a {@code RingBufferAuditSink} with the given capacity. */
  AuditBootstrap ringBuffer(int capacity);

  /**
   * Records the intent to route credential events through the
   * configured audit service. <strong>V00.73 status: no behavioural
   * effect</strong> — {@code CredentialAuditPublisher} already routes
   * through {@code JSentinelServiceResolver.findJSentinelAuditService()}
   * unconditionally. The flag is surfaced in {@code JSentinelRuntime}
   * so the configured intent is visible; future releases (V00.75+)
   * may make it enable per-channel filtering. JavaDoc here is the
   * single source of truth for the no-op semantics — do not mistake
   * this method for a runtime toggle.
   */
  AuditBootstrap credentialEvents(boolean enabled);
}
