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

/**
 * Write-only destination for {@link AuditEvent}s.
 * <p>
 * Sinks are the side-effecting end of the audit pipeline — they log to
 * stderr, append to disk, ship to a SIEM, or buffer in memory. The
 * read-side ({@code query(AuditQuery)}) belongs on
 * {@code JSentinelAuditService}, not here.
 * <p>
 * Implementations <strong>must not throw</strong> from {@link #accept}.
 * A failing sink must catch its own exceptions and degrade silently, so
 * the security flow that emitted the event is never interrupted by a
 * downstream audit problem.
 */
@FunctionalInterface
public interface AuditSink {

  /**
   * Records the given event.
   *
   * @param event non-{@code null} event
   */
  void accept(AuditEvent event);
}
