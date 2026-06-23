package com.svenruppert.jsentinel.events.integration;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.jsentinel.audit.AuditEvent;
import com.svenruppert.jsentinel.audit.JSentinelAuditService;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.api.JSentinelEvent;
import com.svenruppert.jsentinel.events.bus.JSentinelEventBus;
import com.svenruppert.jsentinel.events.bus.JSentinelEventListener;
import com.svenruppert.jsentinel.events.bus.Registration;

import java.util.Objects;
import java.util.Optional;

/**
 * Bus listener that forwards mapped events to the audit service (Konzept §1031).
 * Audit sits <em>on top of</em> the bus as a consumer; this listener is the
 * bridge.
 *
 * <p>Audit-sink failures are isolated (Konzept §779): a throwing
 * {@link JSentinelAuditService} is caught and logged, never propagated back into
 * the dispatch loop.
 *
 * <p>Lives in {@code jSentinel-events} (not {@code jSentinel-core}) because it
 * must see both the bus event types and the core audit model, and
 * {@code jSentinel-core} must not depend on the events module — the dependency
 * runs events → core only.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class AuditEventBusListener
    implements JSentinelEventListener<JSentinelEvent>, HasLogger {

  private final JSentinelAuditService auditService;
  private final AuditEventMapper mapper;

  public AuditEventBusListener(JSentinelAuditService auditService) {
    this(auditService, new AuditEventMapper());
  }

  public AuditEventBusListener(JSentinelAuditService auditService, AuditEventMapper mapper) {
    this.auditService = Objects.requireNonNull(auditService, "auditService");
    this.mapper = Objects.requireNonNull(mapper, "mapper");
  }

  @Override
  public void onJSentinelEvent(JSentinelEvent event) {
    Optional<AuditEvent> audit = mapper.toAuditEvent(event);
    if (audit.isEmpty()) {
      return;
    }
    try {
      auditService.publish(audit.get());
    } catch (RuntimeException sinkFailure) {
      logger().warn("events/audit-sink-failed: {} while auditing {} ({})",
          sinkFailure.getClass().getSimpleName(), event.eventType().value(),
          sinkFailure.getMessage());
    }
  }

  /**
   * Subscribes this listener to the bus for all events.
   *
   * @param bus the event bus
   * @return the subscription registration
   */
  public Registration subscribeTo(JSentinelEventBus bus) {
    return bus.subscribe(JSentinelEvent.class, this);
  }
}
