package eu.jsentinel.jcustos.events.integration;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.bus.JCustosEventBus;
import eu.jsentinel.jcustos.events.bus.JCustosEventListener;
import eu.jsentinel.jcustos.events.bus.Registration;

import java.util.Objects;
import java.util.Optional;

/**
 * Bus listener that forwards mapped events to the audit service (Konzept §1031).
 * Audit sits <em>on top of</em> the bus as a consumer; this listener is the
 * bridge.
 *
 * <p>Audit-sink failures are isolated (Konzept §779): a throwing
 * {@link JCustosAuditService} is caught and logged, never propagated back into
 * the dispatch loop.
 *
 * <p>Lives in {@code jCustos-events} (not {@code jCustos-core}) because it
 * must see both the bus event types and the core audit model, and
 * {@code jCustos-core} must not depend on the events module — the dependency
 * runs events → core only.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class AuditEventBusListener
    implements JCustosEventListener<JCustosEvent>, HasLogger {

  private final JCustosAuditService auditService;
  private final AuditEventMapper mapper;

  public AuditEventBusListener(JCustosAuditService auditService) {
    this(auditService, new AuditEventMapper());
  }

  public AuditEventBusListener(JCustosAuditService auditService, AuditEventMapper mapper) {
    this.auditService = Objects.requireNonNull(auditService, "auditService");
    this.mapper = Objects.requireNonNull(mapper, "mapper");
  }

  @Override
  public void onJCustosEvent(JCustosEvent event) {
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
  public Registration subscribeTo(JCustosEventBus bus) {
    return bus.subscribe(JCustosEvent.class, this);
  }
}
