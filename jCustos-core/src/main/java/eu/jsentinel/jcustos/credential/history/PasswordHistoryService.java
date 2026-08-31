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
package eu.jsentinel.jcustos.credential.history;

import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.secret.SecretValue;

import java.time.Instant;
import java.util.Objects;

/**
 * Coordinates the optional password-history check.
 *
 * <p>Adapters call {@link #evaluate(String, SecretValue, PasswordHistoryPolicy)}
 * with the candidate password <em>before</em> persisting the new hash.
 * If the policy is disabled the service returns
 * {@link PasswordHistoryDecision.Allowed} without touching the
 * store. If enabled it verifies the candidate against each retained
 * verifier through the same {@link PasswordHashingService} used for
 * the normal login path — old envelopes therefore remain readable
 * as long as their algorithm is still registered (CWE-693).</p>
 *
 * <p>After a successful change adapters call
 * {@link #recordNew(String, String, Instant, PasswordHistoryPolicy)}
 * with the freshly produced envelope and the active retention
 * setting. The store enforces the cap via
 * {@link PasswordHistoryStore#appendAndTrim} (CWE-400).</p>
 */
public final class PasswordHistoryService {

  private final PasswordHistoryStore store;
  private final PasswordHashingService hashingService;

  public PasswordHistoryService(
      PasswordHistoryStore store,
      PasswordHashingService hashingService) {
    this.store = Objects.requireNonNull(store, "store");
    this.hashingService = Objects.requireNonNull(hashingService, "hashingService");
  }

  /**
   * Returns {@link PasswordHistoryDecision.Reused} when the supplied
   * candidate verifies against any retained envelope under {@code policy}.
   * History disabled or retention size 0 → always
   * {@link PasswordHistoryDecision.Allowed}.
   */
  public PasswordHistoryDecision evaluate(
      String username,
      SecretValue candidate,
      PasswordHistoryPolicy policy) {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(candidate, "candidate");
    Objects.requireNonNull(policy, "policy");
    if (!policy.enabled()) {
      return PasswordHistoryDecision.Allowed.INSTANCE;
    }
    for (PasswordHistoryEntry entry : store.recent(username, policy.retainLast())) {
      CredentialVerificationResult result =
          hashingService.verify(candidate, entry.encodedHash());
      if (result instanceof CredentialVerificationResult.Verified) {
        return PasswordHistoryDecision.Reused.INSTANCE;
      }
    }
    return PasswordHistoryDecision.Allowed.INSTANCE;
  }

  /**
   * Records the new envelope in the per-user history and trims to the
   * retention size. No-op when {@code policy.enabled()} is false.
   */
  public void recordNew(
      String username,
      String encodedHash,
      Instant when,
      PasswordHistoryPolicy policy) {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(encodedHash, "encodedHash");
    Objects.requireNonNull(when, "when");
    Objects.requireNonNull(policy, "policy");
    if (!policy.enabled()) {
      return;
    }
    store.appendAndTrim(
        username,
        new PasswordHistoryEntry(encodedHash, when),
        policy.retainLast());
  }
}
