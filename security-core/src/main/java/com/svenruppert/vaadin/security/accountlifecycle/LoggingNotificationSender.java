/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.vaadin.security.accountlifecycle;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;

import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Default {@link SecurityNotificationSender} that writes a single
 * INFO line per notification — useful for demos and tests that
 * need lifecycle flows to complete without a real mail provider.
 * <p>
 * The line format mirrors {@code LoggingAuditSink}: a stable
 * {@code NOTIFY type=…} prefix followed by key=value pairs so log
 * scrapers can pivot on the {@link SecurityNotification.Kind} and
 * the attribute keys without parsing free-form text.
 *
 * <p>Plain token values are written verbatim into the line —
 * acceptable for demo / test contexts but obviously unsafe to
 * point at a production log aggregator. Production deployments
 * register their own transport.
 */
@ExperimentalSecurityApi
public final class LoggingNotificationSender implements SecurityNotificationSender {

  private static final Logger DEFAULT_LOGGER =
      Logger.getLogger("com.svenruppert.vaadin.security.accountlifecycle");

  private final Logger logger;

  /** Uses the default {@code accountlifecycle} logger. */
  public LoggingNotificationSender() {
    this(DEFAULT_LOGGER);
  }

  /**
   * @param logger non-null target logger
   */
  public LoggingNotificationSender(Logger logger) {
    this.logger = Objects.requireNonNull(logger, "logger must not be null");
  }

  @Override
  public void send(SecurityNotification notification) {
    if (notification == null) return;
    try {
      logger.log(Level.INFO, format(notification));
    } catch (RuntimeException ignored) {
      // Senders must never throw.
    }
  }

  private static String format(SecurityNotification n) {
    StringBuilder sb = new StringBuilder("NOTIFY ");
    sb.append("type=").append(n.kind().name());
    sb.append(' ').append("subject=").append(n.subjectId().value());
    sb.append(' ').append("tenant=").append(n.tenant().value());
    for (Map.Entry<String, String> entry : n.attributes().entrySet()) {
      String key = entry.getKey();
      String value = entry.getValue();
      if (value == null) continue;
      sb.append(' ').append(key).append('=').append(value);
    }
    return sb.toString();
  }
}
