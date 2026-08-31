/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
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
package eu.jsentinel.jcustos.audit;

import java.time.Instant;
import java.util.Objects;

/**
 * Successful password verification, recorded by the credential audit
 * publisher so audit sinks see the same outcome the
 * {@code LoginAttemptPolicy} recorded.
 *
 * <p>The event carries only metadata that an operator can publicly
 * observe (algorithm, provider id, policy version, pepper presence).
 * Salt, derived key material and the pepper key value itself never
 * appear here (CWE-209 / CWE-522).</p>
 *
 * @param timestamp       UTC creation time
 * @param username        username supplied by the attempt
 * @param clientAddress   remote client address, or {@code null}
 * @param algorithm       algorithm recorded in the verified envelope
 * @param providerId      provider id recorded in the verified envelope
 * @param policyVersion   policy version recorded in the verified envelope
 * @param pepperKeyIdPresent {@code true} when the verified envelope had
 *                           a pepper key id; the value itself is never
 *                           recorded
 * @param rehashRequired  whether the rehash engine flagged this envelope
 *                        for transparent upgrade
 */
public record CredentialVerificationSucceeded(
    Instant timestamp,
    String username,
    String clientAddress,
    String algorithm,
    String providerId,
    int policyVersion,
    boolean pepperKeyIdPresent,
    boolean rehashRequired
) implements AuditEvent {

  public CredentialVerificationSucceeded {
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(algorithm, "algorithm");
    Objects.requireNonNull(providerId, "providerId");
  }
}
