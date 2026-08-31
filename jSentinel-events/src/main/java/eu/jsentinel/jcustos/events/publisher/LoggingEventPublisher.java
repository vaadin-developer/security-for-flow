package eu.jsentinel.jcustos.events.publisher;

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
import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.events.api.SignedJSentinelEventEnvelope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * {@link SignedEnvelopePublisher} that writes one stable, grep-friendly
 * {@code INFO} line per published envelope. Never throws.
 * <p>
 * The line format is intentionally compact and stable so it can be grepped
 * from a deployment log: {@code EVENT envelope=… type=… … payloadHash=…}.
 * It carries envelope <em>metadata only</em> — never the canonical payload
 * and never the signature bytes; every value is passed through
 * {@link LogFieldScrubber} (CWE-117). An absent {@code causationId} is
 * rendered as {@code -}.
 * <p>
 * Mirroring {@code LoggingAuditSink} (R037), the event stream is a named
 * SLF4J logger ({@value #EVENT_LOGGER_NAME}) so operators can route it to
 * its own appender; the {@code (Logger)} constructor remains a
 * test/injection seam.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class LoggingEventPublisher implements SignedEnvelopePublisher, HasLogger {

  /** Event stream name; route this to a dedicated appender in logback/simplelogger. */
  public static final String EVENT_LOGGER_NAME = "eu.jsentinel.jcustos.events";

  private static final Logger DEFAULT_LOGGER = LoggerFactory.getLogger(EVENT_LOGGER_NAME);

  private static final String LINE_PREFIX = "EVENT ";
  private static final String K_ENVELOPE = "envelope";
  private static final String K_TYPE = "type";
  private static final String K_TENANT = "tenant";
  private static final String K_SUBJECT = "subject";
  private static final String K_PRODUCER = "producer";
  private static final String K_SEQUENCE = "seq";
  private static final String K_OCCURRED_AT = "occurredAt";
  private static final String K_CORRELATION = "correlation";
  private static final String K_CAUSATION = "causation";
  private static final String K_KEY = "key";
  private static final String K_ALGORITHM = "alg";
  private static final String K_PAYLOAD_HASH = "payloadHash";
  private static final String ABSENT = "-";

  private final Logger logger;

  public LoggingEventPublisher() {
    this(DEFAULT_LOGGER);
  }

  public LoggingEventPublisher(Logger logger) {
    this.logger = Objects.requireNonNull(logger, "logger");
  }

  @Override
  public Logger logger() {
    return logger;
  }

  @Override
  public void onEnvelope(SignedJSentinelEventEnvelope envelope) {
    if (envelope == null) {
      return;
    }
    try {
      logger.info(format(envelope));
    } catch (RuntimeException ex) {
      // R036: publishers on the bus's fan-out path must never throw, but a
      // failing event logger is a blind spot — report the swallowed failure
      // via the framework logger (the event stream's own logger just failed).
      // No envelope fields in the message.
      HasLogger.staticLogger().warn(
          "events/logging-publisher-failed: dropped an EVENT line because the event logger threw",
          ex);
    }
  }

  private static String format(SignedJSentinelEventEnvelope e) {
    StringBuilder sb = new StringBuilder(LINE_PREFIX);
    appendField(sb, K_ENVELOPE, e.envelopeId().value());
    appendField(sb, K_TYPE, e.eventType().value());
    appendField(sb, K_TENANT, e.tenantId().value());
    appendField(sb, K_SUBJECT, e.subjectId().value());
    appendField(sb, K_PRODUCER, e.producerId().value());
    appendField(sb, K_SEQUENCE, String.valueOf(e.sequence().value()));
    appendField(sb, K_OCCURRED_AT, e.occurredAt().toString());
    appendField(sb, K_CORRELATION, e.correlationId().value());
    appendField(sb, K_CAUSATION, e.causationId() == null ? ABSENT : e.causationId().value());
    appendField(sb, K_KEY, e.keyId().value());
    appendField(sb, K_ALGORITHM, e.signatureAlgorithm().value());
    appendField(sb, K_PAYLOAD_HASH, e.canonicalPayloadHash());
    return sb.toString();
  }

  private static void appendField(StringBuilder sb, String key, String value) {
    if (sb.length() > LINE_PREFIX.length()) {
      sb.append(' ');
    }
    sb.append(key).append('=').append(LogFieldScrubber.scrub(value));
  }
}
