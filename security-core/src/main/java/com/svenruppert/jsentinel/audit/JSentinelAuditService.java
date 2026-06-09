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
package com.svenruppert.jsentinel.audit;

import java.util.List;

/**
 * Read/write facade for security audit events.
 * <p>
 * The write side ({@link #publish(AuditEvent)}) is the canonical entry
 * point for every framework emit-site. Implementations typically fan the
 * event out to one or more {@link AuditSink}s. The read side
 * ({@link #query(AuditQuery)}) is optional — implementations that do not
 * retain events should return an empty list.
 * <p>
 * Implementations <strong>must not throw</strong> from either method.
 * Audit failure must never break the security flow that emitted the
 * event; an empty list is acceptable when no retained data is available.
 */
public interface JSentinelAuditService {

  /**
   * Records the given event. Never throws.
   *
   * @param event non-{@code null} typed audit event
   */
  void publish(AuditEvent event);

  /**
   * Returns retained events matching {@code query}, oldest first.
   * Implementations that do not retain events return an empty list.
   *
   * @param query filter, never {@code null}
   * @return retained matching events, never {@code null}
   */
  List<AuditEvent> query(AuditQuery query);
}
