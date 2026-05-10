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

/**
 * SPI for sinking {@link SecurityAuditEvent}s.
 * <p>
 * Implementations may persist, forward, filter, or simply ignore events.
 * A {@link SecurityAuditService} <strong>must not throw</strong> from
 * {@link #record(SecurityAuditEvent)} — failure to record an audit event
 * must never break the security flow that emitted it.
 * <p>
 * If your sink can fail (e.g. database, network), catch the failure
 * inside {@link #record(SecurityAuditEvent)} and fall back to a local
 * log. The framework's default
 * ({@link NoopSecurityAuditService}) does nothing; the
 * provided {@link LoggingSecurityAuditService} writes a single
 * {@link java.util.logging.Logger} line per event and never throws.
 */
@FunctionalInterface
public interface SecurityAuditService {

  /**
   * Records a security event.
   *
   * @param event non-{@code null} event
   */
  void record(SecurityAuditEvent event);
}
