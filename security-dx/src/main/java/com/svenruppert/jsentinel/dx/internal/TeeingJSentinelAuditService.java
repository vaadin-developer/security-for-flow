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
package com.svenruppert.jsentinel.dx.internal;

import com.svenruppert.jsentinel.audit.AuditEvent;
import com.svenruppert.jsentinel.audit.AuditQuery;
import com.svenruppert.jsentinel.audit.JSentinelAuditService;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Internal {@link JSentinelAuditService} that forwards every
 * {@link #publish(AuditEvent)} call to a primary service and zero or
 * more sibling services. Queries are served by the primary service
 * only.
 *
 * <p>Used by {@link AbstractJSentinelBootstrap} when the fluent
 * {@code .audit(...)} configuration mixes a
 * {@code StoreBackedJSentinelAuditService} with one or more sink-only
 * services. The core {@code CompositeAuditService} signature
 * {@code (RingBufferAuditSink, AuditSink...)} cannot model that
 * mix; the workaround is documented in Konzept §6.2.
 *
 * <p>A failing sibling never propagates — audit failure must not
 * interrupt the security flow.
 *
 * @since 00.73.00
 */
final class TeeingJSentinelAuditService implements JSentinelAuditService {

  private final JSentinelAuditService primary;
  private final List<JSentinelAuditService> siblings;

  TeeingJSentinelAuditService(JSentinelAuditService primary, JSentinelAuditService... siblings) {
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
    for (JSentinelAuditService sibling : siblings) {
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
  JSentinelAuditService primary() {
    return primary;
  }

  /** Test/diagnostics helper. */
  List<JSentinelAuditService> siblings() {
    return siblings;
  }
}
