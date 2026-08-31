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

import eu.jsentinel.jcustos.credential.input.PasswordInputViolation;
import eu.jsentinel.jcustos.credential.lifecycle.CredentialLifecycleDecision;

import java.util.Objects;

/**
 * Outcome of {@link PasswordChangeService#change}.
 *
 * <p>Sealed so adapters pattern-match exhaustively. Every failure
 * variant collapses to a generic public response at the adapter
 * boundary; the differentiated structural reason stays in audit
 * (CWE-203 / CWE-209).</p>
 */
public sealed interface PasswordChangeResult
    permits PasswordChangeResult.Succeeded,
            PasswordChangeResult.CurrentPasswordRejected,
            PasswordChangeResult.NewPasswordRejected,
            PasswordChangeResult.Blocked,
            PasswordChangeResult.Conflict,
            PasswordChangeResult.NotFound {

  /**
   * Password successfully changed. {@code sessionDecision} is the
   * recommended action for the calling adapter.
   */
  record Succeeded(SessionHandlingDecision sessionDecision)
      implements PasswordChangeResult {

    public Succeeded {
      Objects.requireNonNull(sessionDecision, "sessionDecision");
    }
  }

  /**
   * Re-authentication failed — the supplied current password does not
   * verify (CWE-620). The store is untouched.
   */
  record CurrentPasswordRejected() implements PasswordChangeResult {
    public static final CurrentPasswordRejected INSTANCE = new CurrentPasswordRejected();
  }

  /**
   * The new password violated the input policy (length, control chars,
   * etc.) and was rejected before hashing.
   */
  record NewPasswordRejected(PasswordInputViolation violation)
      implements PasswordChangeResult {

    public NewPasswordRejected {
      Objects.requireNonNull(violation, "violation");
    }
  }

  /**
   * The current lifecycle status forbids credential changes (e.g.
   * {@code DISABLED}, {@code COMPROMISED}).
   */
  record Blocked(CredentialLifecycleDecision decision)
      implements PasswordChangeResult {

    public Blocked {
      Objects.requireNonNull(decision, "decision");
    }
  }

  /**
   * A concurrent password change won the compare-and-swap race. The
   * caller may safely retry (CWE-362).
   */
  record Conflict() implements PasswordChangeResult {
    public static final Conflict INSTANCE = new Conflict();
  }

  /**
   * No credential exists under the supplied username.
   */
  record NotFound() implements PasswordChangeResult {
    public static final NotFound INSTANCE = new NotFound();
  }
}
