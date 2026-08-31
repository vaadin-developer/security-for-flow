package eu.jsentinel.jcustos.audit.integrity.listener;

/*-
 * #%L
 * jCustos Audit Integrity — tamper-evident audit
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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
import eu.jsentinel.jcustos.audit.integrity.chain.AuditChainAppender;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.bus.JCustosEventBus;
import eu.jsentinel.jcustos.events.bus.JCustosEventListener;
import eu.jsentinel.jcustos.events.bus.Registration;
import eu.jsentinel.jcustos.events.codec.JCustosEventCanonicalizer;
import eu.jsentinel.jcustos.events.codec.PayloadCodec;
import eu.jsentinel.jcustos.events.codec.CanonicalJsonPayloadCodec;
import eu.jsentinel.jcustos.events.codec.RecordReflectionCanonicalizer;

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
@ExperimentalJCustosApi
public final class AuditIntegrityListener
    implements JCustosEventListener<JCustosEvent>, HasLogger {

  /** Payload type of chained bus events. */
  public static final String PAYLOAD_TYPE = "jsentinel-event/canonical-json/v1";

  private final AuditChainAppender appender;
  private final AuditRelevancePolicy policy;
  private final JCustosEventCanonicalizer canonicalizer;
  private final PayloadCodec codec;

  /** Defaults: {@link AuditRelevancePolicy#auditRelevantDefaults()} + the canonical-JSON pipeline. */
  public AuditIntegrityListener(AuditChainAppender appender) {
    this(appender, AuditRelevancePolicy.auditRelevantDefaults(),
        new RecordReflectionCanonicalizer(), new CanonicalJsonPayloadCodec());
  }

  public AuditIntegrityListener(AuditChainAppender appender,
      AuditRelevancePolicy policy, JCustosEventCanonicalizer canonicalizer,
      PayloadCodec codec) {
    this.appender = Objects.requireNonNull(appender, "appender");
    this.policy = Objects.requireNonNull(policy, "policy");
    this.canonicalizer = Objects.requireNonNull(canonicalizer, "canonicalizer");
    this.codec = Objects.requireNonNull(codec, "codec");
  }

  @Override
  public void onJCustosEvent(JCustosEvent event) {
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
  public Registration subscribeTo(JCustosEventBus bus) {
    return bus.subscribe(JCustosEvent.class, this);
  }
}
