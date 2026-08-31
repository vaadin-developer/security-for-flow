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

import eu.jsentinel.jcustos.credential.password.RehashReason;

import java.time.Instant;
import java.util.Objects;

/**
 * A successful verification triggered a transparent rehash of the
 * stored credential. Emitted after the credential store has actually
 * accepted the new envelope; in-memory demo stores publish this on
 * every successful rehash too so audit timelines stay consistent.
 *
 * @param timestamp           UTC creation time
 * @param username            username whose credential was rehashed
 * @param fromAlgorithm       algorithm of the previous envelope
 * @param toAlgorithm         algorithm of the new envelope
 * @param reason              dominant {@link RehashReason} that drove
 *                            the upgrade
 * @param targetPolicyVersion policy version the new envelope targets
 */
public record CredentialRehashed(
    Instant timestamp,
    String username,
    String fromAlgorithm,
    String toAlgorithm,
    RehashReason reason,
    int targetPolicyVersion
) implements AuditEvent {

  public CredentialRehashed {
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(fromAlgorithm, "fromAlgorithm");
    Objects.requireNonNull(toAlgorithm, "toAlgorithm");
    Objects.requireNonNull(reason, "reason");
    if (targetPolicyVersion < 1) {
      throw new IllegalArgumentException("targetPolicyVersion must be >= 1");
    }
  }
}
