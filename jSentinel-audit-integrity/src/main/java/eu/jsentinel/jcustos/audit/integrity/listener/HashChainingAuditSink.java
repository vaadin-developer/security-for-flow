package eu.jsentinel.jcustos.audit.integrity.listener;

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
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditSink;
import eu.jsentinel.jcustos.audit.integrity.chain.AuditChainAppender;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

import java.util.Objects;

/**
 * {@link AuditSink} that chains every core audit event — this is how the
 * V00.70 persistent-audit path gains tamper evidence ON TOP of its existing
 * sinks ("ergänzt persistentes Audit, ersetzt es nicht"): register it next
 * to the ring-buffer/store sinks in a composite audit service.
 * <p>
 * Honors the {@link AuditSink} contract to the letter: {@code accept} never
 * throws — a full chain store or a non-canonicalizable event is logged
 * ({@code audit-integrity/audit-sink-append-failed}) and swallowed.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class HashChainingAuditSink implements AuditSink, HasLogger {

  /** Payload type of chained core audit events. */
  public static final String PAYLOAD_TYPE_AUDIT = "jsentinel-audit-event/v1";

  private final AuditChainAppender appender;

  public HashChainingAuditSink(AuditChainAppender appender) {
    this.appender = Objects.requireNonNull(appender, "appender");
  }

  @Override
  public void accept(AuditEvent event) {
    if (event == null) {
      return;
    }
    try {
      appender.append(PAYLOAD_TYPE_AUDIT, AuditEventCanonicalizer.canonicalize(event));
    } catch (RuntimeException chainFailure) {
      // AuditSink contract: degrade silently toward the caller, loudly in
      // the log — a lost chain link is a forensic blind spot. No field values.
      logger().warn("audit-integrity/audit-sink-append-failed: {} while chaining {} ({})",
          chainFailure.getClass().getSimpleName(), event.getClass().getSimpleName(),
          chainFailure.getMessage());
    }
  }
}
