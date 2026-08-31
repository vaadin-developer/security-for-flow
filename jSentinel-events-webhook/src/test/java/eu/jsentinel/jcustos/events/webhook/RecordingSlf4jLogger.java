package eu.jsentinel.jcustos.events.webhook;

/*-
 * #%L
 * jCustos Events — Webhook exporter
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
import java.util.Collections;
import java.util.List;

/**
 * Hand-written SLF4J {@link org.slf4j.Logger} test double (no mock framework)
 * recording the final, placeholder-substituted message of every logging call.
 * Module-local copy of the jCustos-events seam-test double — used to pin
 * the scrubbed WARN lines of {@link WebhookEventPublisher}.
 */
class RecordingSlf4jLogger extends AbstractLogger {

  private final List<String> messages = Collections.synchronizedList(new ArrayList<>());

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

  List<String> messages() {
    synchronized (messages) {
      return List.copyOf(messages);
    }
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
