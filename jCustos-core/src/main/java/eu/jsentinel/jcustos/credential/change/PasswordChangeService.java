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
package eu.jsentinel.jcustos.credential.change;

import eu.jsentinel.jcustos.credential.input.PasswordInputPolicy;
import eu.jsentinel.jcustos.credential.input.PasswordInputValidationResult;
import eu.jsentinel.jcustos.credential.input.PasswordInputValidator;
import eu.jsentinel.jcustos.credential.lifecycle.CredentialLifecycleDecision;
import eu.jsentinel.jcustos.credential.lifecycle.CredentialLifecycleService;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.store.CredentialRecord;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.CredentialStore;
import eu.jsentinel.jcustos.credential.store.CredentialUpdateResult;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Atomic, policy-driven password change.
 *
 * <h2>Flow</h2>
 * <ol>
 *   <li>Load the credential by username; missing → {@code NotFound}.</li>
 *   <li>Consult the lifecycle service; status that forbids change
 *       (LOCKED / COMPROMISED / DISABLED) → {@code Blocked}.</li>
 *   <li>Re-authenticate by verifying the supplied current password
 *       (CWE-620). Anything but {@code Verified} →
 *       {@code CurrentPasswordRejected}.</li>
 *   <li>Validate the proposed new password through the input policy.
 *       A rejection here surfaces the structural reason.</li>
 *   <li>Hash the new password through {@link PasswordHashingService}.</li>
 *   <li>Compare-and-swap the encoded hash with the original envelope as
 *       witness. Stale → {@code Conflict} (CWE-362).</li>
 *   <li>If the credential was {@code MUST_CHANGE}, clear it to
 *       {@code ACTIVE} through the lifecycle service. Failure to clear
 *       does <em>not</em> roll back the hash update — the password is
 *       already new; the next login will trigger the same clear.</li>
 *   <li>Return {@code Succeeded(INVALIDATE_OTHER_SESSIONS)}.</li>
 * </ol>
 */
public final class PasswordChangeService {

  private final CredentialStore store;
  private final PasswordHashingService hashingService;
  private final PasswordInputValidator inputValidator;
  private final PasswordInputPolicy inputPolicy;
  private final CredentialLifecycleService lifecycleService;
  private final Clock clock;

  public PasswordChangeService(
      CredentialStore store,
      PasswordHashingService hashingService,
      PasswordInputValidator inputValidator,
      PasswordInputPolicy inputPolicy,
      CredentialLifecycleService lifecycleService,
      Clock clock) {
    this.store = Objects.requireNonNull(store, "store");
    this.hashingService = Objects.requireNonNull(hashingService, "hashingService");
    this.inputValidator = Objects.requireNonNull(inputValidator, "inputValidator");
    this.inputPolicy = Objects.requireNonNull(inputPolicy, "inputPolicy");
    this.lifecycleService = Objects.requireNonNull(lifecycleService, "lifecycleService");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  public PasswordChangeResult change(PasswordChangeCommand command) {
    Objects.requireNonNull(command, "command");

    Optional<CredentialRecord> existing = store.findByUsername(command.username());
    if (existing.isEmpty()) {
      return PasswordChangeResult.NotFound.INSTANCE;
    }
    CredentialRecord record = existing.get();

    CredentialLifecycleDecision lifecycle = lifecycleService.decide(record.status());
    if (lifecycle instanceof CredentialLifecycleDecision.BlockedTemporary
        || lifecycle instanceof CredentialLifecycleDecision.BlockedPermanent) {
      return new PasswordChangeResult.Blocked(lifecycle);
    }

    CredentialVerificationResult verifyResult = hashingService.verify(
        command.currentPassword(), record.encodedHash());
    if (!(verifyResult instanceof CredentialVerificationResult.Verified)) {
      return PasswordChangeResult.CurrentPasswordRejected.INSTANCE;
    }

    PasswordInputValidationResult inputCheck =
        inputValidator.validate(command.newPassword(), inputPolicy);
    if (inputCheck instanceof PasswordInputValidationResult.Rejected rejected) {
      return new PasswordChangeResult.NewPasswordRejected(rejected.violation());
    }

    PasswordHashResult newHash = hashingService.hash(command.newPassword());

    Instant now = Instant.now(clock);
    CredentialUpdateResult update = store.updateHashIfCurrent(
        command.username(), record.encodedHash(), newHash.encodedHash(), now);
    if (!(update instanceof CredentialUpdateResult.Updated)) {
      return PasswordChangeResult.Conflict.INSTANCE;
    }

    // Clear MUST_CHANGE if applicable. Failure here is non-fatal:
    // the password update has already succeeded, and the next
    // verification will re-evaluate the lifecycle.
    if (record.status() == CredentialStatus.MUST_CHANGE) {
      lifecycleService.transition(command.username(),
          CredentialStatus.MUST_CHANGE, CredentialStatus.ACTIVE,
          "password-changed");
    }

    return new PasswordChangeResult.Succeeded(
        SessionHandlingDecision.INVALIDATE_OTHER_SESSIONS);
  }
}
