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
package com.svenruppert.vaadin.security.audit;

import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * {@link SecurityAuditService} that writes one {@link java.util.logging}
 * line per event. Uses {@code j.u.l.} so {@code security-core} stays
 * dependency-free; applications that prefer SLF4J / Log4j can either
 * install a {@code java.util.logging} bridge or provide their own
 * SPI implementation.
 * <p>
 * The line format is intentionally compact and stable so it can be
 * grepped or piped into a log shipper:
 * <pre>{@code
 *   AUDIT type=LOGIN_FAILURE subject=alice route=/login decision=DENIED attrs={reason=bad_password}
 * }</pre>
 *
 * <p>This service never throws.
 */
public final class LoggingSecurityAuditService implements SecurityAuditService {

  /** Logger name shared by every instance — operators can target it directly. */
  public static final String LOGGER_NAME = "security.audit";

  private final Logger logger;
  private final Level level;

  /** Default — INFO level, shared logger. */
  public LoggingSecurityAuditService() {
    this(Logger.getLogger(LOGGER_NAME), Level.INFO);
  }

  /** Custom logger / level — useful for tests. */
  public LoggingSecurityAuditService(Logger logger, Level level) {
    this.logger = Objects.requireNonNull(logger, "logger");
    this.level = Objects.requireNonNull(level, "level");
  }

  @Override
  public void record(SecurityAuditEvent event) {
    if (event == null) return;
    if (!logger.isLoggable(level)) return;
    try {
      logger.log(level, format(event));
    } catch (RuntimeException loggerFailure) {
      // never propagate from an audit sink
    }
  }

  static String format(SecurityAuditEvent e) {
    StringBuilder sb = new StringBuilder("AUDIT");
    sb.append(" type=").append(e.type());
    if (e.subjectId() != null)     sb.append(" subjectId=").append(e.subjectId());
    if (e.username() != null)      sb.append(" subject=").append(e.username());
    if (e.route() != null)         sb.append(" route=").append(e.route());
    if (e.decision() != null)      sb.append(" decision=").append(e.decision());
    if (e.clientAddress() != null) sb.append(" client=").append(e.clientAddress());
    if (e.sessionId() != null)     sb.append(" session=").append(e.sessionId());
    if (!e.attributes().isEmpty()) sb.append(" attrs={").append(formatAttrs(e.attributes())).append('}');
    return sb.toString();
  }

  private static String formatAttrs(Map<String, String> attrs) {
    return attrs.entrySet().stream()
        .map(entry -> entry.getKey() + "=" + entry.getValue())
        .collect(Collectors.joining(", "));
  }
}
