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

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Internal {@link JCustosAuditService} that forwards every
 * {@link #publish(AuditEvent)} call to a primary service and zero or
 * more sibling services. Queries are served by the primary service
 * only.
 *
 * <p>Used by {@link AbstractJCustosBootstrap} when the fluent
 * {@code .audit(...)} configuration mixes a
 * {@code StoreBackedJCustosAuditService} with one or more sink-only
 * services. The core {@code CompositeAuditService} signature
 * {@code (RingBufferAuditSink, AuditSink...)} cannot model that
 * mix; the workaround is documented in Konzept §6.2.
 *
 * <p>A failing sibling never propagates — audit failure must not
 * interrupt the security flow.
 *
 * @since 00.73.00
 */
final class TeeingJCustosAuditService implements JCustosAuditService {

  private final JCustosAuditService primary;
  private final List<JCustosAuditService> siblings;

  TeeingJCustosAuditService(JCustosAuditService primary, JCustosAuditService... siblings) {
    this.primary = Objects.requireNonNull(primary, "primary");
    this.siblings = siblings == null
        ? List.of()
        : List.copyOf(Arrays.asList(siblings));
  }

  @Override
  public void publish(AuditEvent event) {
    if (event == null) {
      return;
    }
    try {
      primary.publish(event);
    } catch (RuntimeException ignored) {
      // never propagate
    }
    for (JCustosAuditService sibling : siblings) {
      try {
        sibling.publish(event);
      } catch (RuntimeException ignored) {
        // never propagate
      }
    }
  }

  @Override
  public List<AuditEvent> query(AuditQuery query) {
    Objects.requireNonNull(query, "query");
    return new ArrayList<>(primary.query(query));
  }

  /** Test/diagnostics helper. */
  JCustosAuditService primary() {
    return primary;
  }

  /** Test/diagnostics helper. */
  List<JCustosAuditService> siblings() {
    return siblings;
  }
}
