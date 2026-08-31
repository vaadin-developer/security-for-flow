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
 * An adapter challenged the subject for a step-up authentication —
 * either via an HTTP {@code 401 + WWW-Authenticate} response (REST) or
 * by rerouting to a configured step-up route (Vaadin).
 *
 * <p>Emitted by the adapter <em>in addition to</em> the coarse
 * {@link AccessDenied} event. Structured fields ({@code method},
 * {@code reason}) avoid the fragile colon-parsing of the
 * {@code AccessDenied.reason} string, so audit consumers (Grafana,
 * SIEM) can pivot on the mechanism without regex.
 *
 * @param timestamp UTC creation time, never {@code null}
 * @param subjectId subject identifier, or {@code null} for anonymous
 * @param route     navigation route or REST path that triggered the
 *                  challenge, or {@code null}
 * @param method    step-up mechanism token ({@code "MFA"},
 *                  {@code "REAUTH"}, …) — non-blank
 * @param reason    adapter-neutral diagnostic from the policy
 *                  decision, possibly empty
 */
public record StepUpChallenged(
    Instant timestamp,
    String subjectId,
    String route,
    String method,
    String reason
) implements AuditEvent {

  public StepUpChallenged {
    Objects.requireNonNull(timestamp, "timestamp");
    if (method == null || method.isBlank()) {
      throw new IllegalArgumentException("method must not be blank");
    }
    reason = reason == null ? "" : reason;
  }
}
