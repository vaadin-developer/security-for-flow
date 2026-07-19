package com.svenruppert.jsentinel.events.publisher;

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
import com.svenruppert.jsentinel.audit.LogFieldScrubber;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * {@link JSentinelAlertSink} that writes a single {@code INFO} line per alert
 * to the named alert stream. Never throws.
 * <p>
 * The line format is intentionally compact and stable so it can be grepped
 * from a deployment log: {@code ALERT type=… severity=… tenant=… subject=…
 * event=… detail=…}; every value is passed through {@link LogFieldScrubber}
 * (CWE-117).
 * <p>
 * Mirroring {@code LoggingAuditSink} (R037), the alert stream is a named
 * SLF4J logger ({@value #ALERT_LOGGER_NAME}) so operators can route it to a
 * dedicated appender; the {@code (Logger)} constructor remains a
 * test/injection seam.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class LoggingAlertSink implements JSentinelAlertSink {

  /** Alert stream name; route this to a dedicated appender in logback/simplelogger. */
  public static final String ALERT_LOGGER_NAME = "com.svenruppert.jsentinel.alerts";

  private static final Logger DEFAULT_LOGGER = LoggerFactory.getLogger(ALERT_LOGGER_NAME);

  private static final String LINE_PREFIX = "ALERT ";
  private static final String K_TYPE = "type";
  private static final String K_SEVERITY = "severity";
  private static final String K_TENANT = "tenant";
  private static final String K_SUBJECT = "subject";
  private static final String K_EVENT = "event";
  private static final String K_DETAIL = "detail";

  private final Logger logger;

  public LoggingAlertSink() {
    this(DEFAULT_LOGGER);
  }

  public LoggingAlertSink(Logger logger) {
    this.logger = Objects.requireNonNull(logger, "logger");
  }

  @Override
  public void accept(JSentinelAlert alert) {
    if (alert == null) {
      return;
    }
    try {
      logger.info(format(alert));
    } catch (RuntimeException ex) {
      // R036: sinks must never throw, but a failing alert sink is a
      // security-relevant blind spot — report the swallowed failure via the
      // framework logger (the alert stream's own logger just failed). No
      // alert fields in the message.
      HasLogger.staticLogger().warn(
          "events/alert-log-failed: dropped an ALERT line because the alert logger threw", ex);
    }
  }

  private static String format(JSentinelAlert alert) {
    StringBuilder sb = new StringBuilder(LINE_PREFIX);
    appendField(sb, K_TYPE, alert.eventType().value());
    appendField(sb, K_SEVERITY, alert.severity().name());
    appendField(sb, K_TENANT, alert.tenantId().value());
    appendField(sb, K_SUBJECT, alert.subjectId().value());
    appendField(sb, K_EVENT, alert.eventId().value());
    appendField(sb, K_DETAIL, alert.detail());
    return sb.toString();
  }

  private static void appendField(StringBuilder sb, String key, String value) {
    if (sb.length() > LINE_PREFIX.length()) {
      sb.append(' ');
    }
    sb.append(key).append('=').append(LogFieldScrubber.scrub(value));
  }
}
