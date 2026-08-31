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
package eu.jsentinel.jcustos.audit;

import java.time.Instant;
import java.util.Objects;

/**
 * Access to a protected route or endpoint was refused.
 *
 * @param timestamp UTC creation time, never {@code null}
 * @param subjectId subject identifier, or {@code null} for anonymous
 * @param route     navigation route or REST path, or {@code null}
 * @param reason    short reason key (e.g. {@code "Unauthenticated"},
 *                  {@code "MissingRole"}), or {@code null}
 */
public record AccessDenied(
    Instant timestamp,
    String subjectId,
    String route,
    String reason
) implements AuditEvent {

  public AccessDenied {
    Objects.requireNonNull(timestamp, "timestamp");
  }
}
