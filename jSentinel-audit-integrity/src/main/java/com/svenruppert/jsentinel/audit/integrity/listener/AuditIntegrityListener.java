package com.svenruppert.jsentinel.audit.integrity.listener;

/*-
 * #%L
 * jSentinel Audit Integrity — tamper-evident audit
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
import com.svenruppert.jsentinel.audit.integrity.chain.AuditChainAppender;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.api.JSentinelEvent;
import com.svenruppert.jsentinel.events.bus.JSentinelEventBus;
import com.svenruppert.jsentinel.events.bus.JSentinelEventListener;
import com.svenruppert.jsentinel.events.bus.Registration;
import com.svenruppert.jsentinel.events.codec.JSentinelEventCanonicalizer;
import com.svenruppert.jsentinel.events.codec.PayloadCodec;
import com.svenruppert.jsentinel.events.codec.CanonicalJsonPayloadCodec;
import com.svenruppert.jsentinel.events.codec.RecordReflectionCanonicalizer;

import java.util.Objects;

/**
 * Bus listener that turns audit-relevant security events into hash-chained
 * audit entries (Konzept goal 7: the {@code AuditIntegrityListener}).
 * Konzept separation: the envelope signature protects the event in
 * <em>transport</em>; the chain this listener feeds is the
 * tamper-resistant <em>historical record</em>.
 * <p>
 * Structure mirrors {@code AuditEventBusListener}: constructor injection,
 * a filter ({@link AuditRelevancePolicy}), and strict failure isolation —
 * a full chain store or a canonicalization failure is logged
 * ({@code audit-integrity/append-failed}) and never propagated into the
 * dispatch loop.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class AuditIntegrityListener
    implements JSentinelEventListener<JSentinelEvent>, HasLogger {

  /** Payload type of chained bus events. */
  public static final String PAYLOAD_TYPE = "jsentinel-event/canonical-json/v1";

  private final AuditChainAppender appender;
  private final AuditRelevancePolicy policy;
  private final JSentinelEventCanonicalizer canonicalizer;
  private final PayloadCodec codec;

  /** Defaults: {@link AuditRelevancePolicy#auditRelevantDefaults()} + the canonical-JSON pipeline. */
  public AuditIntegrityListener(AuditChainAppender appender) {
    this(appender, AuditRelevancePolicy.auditRelevantDefaults(),
        new RecordReflectionCanonicalizer(), new CanonicalJsonPayloadCodec());
  }

  public AuditIntegrityListener(AuditChainAppender appender,
      AuditRelevancePolicy policy, JSentinelEventCanonicalizer canonicalizer,
      PayloadCodec codec) {
    this.appender = Objects.requireNonNull(appender, "appender");
    this.policy = Objects.requireNonNull(policy, "policy");
    this.canonicalizer = Objects.requireNonNull(canonicalizer, "canonicalizer");
    this.codec = Objects.requireNonNull(codec, "codec");
  }

  @Override
  public void onJSentinelEvent(JSentinelEvent event) {
    if (event == null || !policy.isAuditRelevant(event)) {
      return;
    }
    try {
      appender.append(PAYLOAD_TYPE, codec.encode(canonicalizer.canonicalize(event)));
    } catch (RuntimeException chainFailure) {
      // Never break the dispatch loop — a failing chain is a forensic blind
      // spot, not a reason to abort security processing. No payload in the log.
      logger().warn("audit-integrity/append-failed: {} while chaining {} ({})",
          chainFailure.getClass().getSimpleName(), event.eventType().value(),
          chainFailure.getMessage());
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
