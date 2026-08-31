/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.audit;

import eu.jsentinel.jcustos.credential.store.CredentialStatus;

import java.time.Instant;
import java.util.Objects;

/**
 * Credential lifecycle status transitioned from {@code fromStatus} to
 * {@code toStatus}.
 *
 * <p>Carries only the structural state names; no password material or
 * envelope content (CWE-209 / CWE-522).</p>
 *
 * @param timestamp  UTC creation time
 * @param username   credential identifier
 * @param fromStatus previous status
 * @param toStatus   new status
 * @param reason     short structural reason key (e.g.
 *                   {@code "force-change"}, {@code "compromised"},
 *                   {@code "rehash-completed"}), or {@code null}
 */
public record CredentialStatusChanged(
    Instant timestamp,
    String username,
    CredentialStatus fromStatus,
    CredentialStatus toStatus,
    String reason
) implements AuditEvent {

  public CredentialStatusChanged {
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(fromStatus, "fromStatus");
    Objects.requireNonNull(toStatus, "toStatus");
  }
}
