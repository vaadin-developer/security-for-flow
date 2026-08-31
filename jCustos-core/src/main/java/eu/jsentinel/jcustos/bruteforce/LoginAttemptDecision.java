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
package eu.jsentinel.jcustos.bruteforce;

import java.time.Duration;
import java.util.Objects;

/**
 * Outcome of {@link LoginAttemptPolicy#beforeAttempt(LoginAttemptContext)}.
 * <p>
 * Sealed so callers can {@code switch} exhaustively without a default
 * case — a future variant for, say, "rate-limited per IP only" forces
 * a compile error at every existing call site.
 */
public sealed interface LoginAttemptDecision
    permits LoginAttemptDecision.Allowed,
            LoginAttemptDecision.LockedOut {

  /** The attempt may proceed. */
  record Allowed() implements LoginAttemptDecision {

    /** Shared singleton — there is only one shape of {@code Allowed}. */
    public static final Allowed INSTANCE = new Allowed();
  }

  /**
   * The caller is locked out. The handler must skip the actual credential
   * check and respond with a generic "too many failed attempts" error.
   *
   * @param remaining       remaining time before the lockout lifts;
   *                        non-{@code null}, non-negative
   * @param failedAttempts  total failures observed for the locked key —
   *                        informational, never echoed to clients
   */
  record LockedOut(Duration remaining, int failedAttempts) implements LoginAttemptDecision {

    public LockedOut {
      Objects.requireNonNull(remaining, "remaining");
      if (remaining.isNegative()) {
        throw new IllegalArgumentException("remaining must be >= 0");
      }
      if (failedAttempts < 0) {
        throw new IllegalArgumentException("failedAttempts must be >= 0");
      }
    }
  }

  /** Convenience for the singleton {@link Allowed}. */
  static Allowed allowed() {
    return Allowed.INSTANCE;
  }

  /**
   * Convenience for {@link LockedOut}.
   *
   * @param remaining      time until the lockout window expires
   * @param failedAttempts number of failed attempts that caused the lockout
   * @return a {@link LockedOut} decision carrying both values
   */
  static LockedOut lockedOut(Duration remaining, int failedAttempts) {
    return new LockedOut(remaining, failedAttempts);
  }
}
