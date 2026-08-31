package eu.jsentinel.jcustos.events.publisher;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
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

import org.slf4j.Marker;
import org.slf4j.event.Level;
import org.slf4j.helpers.AbstractLogger;
import org.slf4j.helpers.MessageFormatter;

import java.util.ArrayList;
import java.util.List;

/**
 * Hand-written SLF4J {@link org.slf4j.Logger} test double (no mock framework)
 * that records the final, placeholder-substituted message of every logging
 * call. Module-local copy of the jCustos-core seam-test double (that one
 * lives in core's unpublished test sources) — used to pin the EVENT / ALERT
 * lines of {@link LoggingEventPublisher} and {@link LoggingAlertSink}.
 *
 * <p>Extends {@link AbstractLogger}, which routes every level overload through
 * {@link #handleNormalizedLoggingCall}, so only that one method plus the
 * level predicates need an implementation.
 */
class RecordingSlf4jLogger extends AbstractLogger {

  final List<String> messages = new ArrayList<>();

  RecordingSlf4jLogger() {
    this.name = "recording";
  }

  @Override
  protected String getFullyQualifiedCallerName() {
    return RecordingSlf4jLogger.class.getName();
  }

  @Override
  protected void handleNormalizedLoggingCall(Level level, Marker marker,
      String messagePattern, Object[] arguments, Throwable throwable) {
    messages.add(arguments == null || arguments.length == 0
        ? messagePattern
        : MessageFormatter.basicArrayFormat(messagePattern, arguments));
  }

  /** @return the single recorded message, asserting exactly one was logged. */
  String firstMessage() {
    if (messages.size() != 1) {
      throw new AssertionError("expected exactly one log line, got: " + messages);
    }
    return messages.get(0);
  }

  @Override public boolean isTraceEnabled() { return true; }
  @Override public boolean isTraceEnabled(Marker marker) { return true; }
  @Override public boolean isDebugEnabled() { return true; }
  @Override public boolean isDebugEnabled(Marker marker) { return true; }
  @Override public boolean isInfoEnabled() { return true; }
  @Override public boolean isInfoEnabled(Marker marker) { return true; }
  @Override public boolean isWarnEnabled() { return true; }
  @Override public boolean isWarnEnabled(Marker marker) { return true; }
  @Override public boolean isErrorEnabled() { return true; }
  @Override public boolean isErrorEnabled(Marker marker) { return true; }
}
