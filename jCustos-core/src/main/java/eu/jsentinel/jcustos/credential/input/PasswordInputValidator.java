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
package eu.jsentinel.jcustos.credential.input;

import eu.jsentinel.jcustos.credential.secret.SecretValue;

import java.util.Objects;

/**
 * Checks password input against the {@link PasswordInputPolicy}.
 *
 * <p>Validation runs before any KDF call so cheap structural problems
 * never trigger expensive hashing (CWE-20 / CWE-400).</p>
 *
 * <p>The validator works in two modes:</p>
 * <ul>
 *   <li>{@link #validate(SecretValue, PasswordInputPolicy)} for the
 *       SecretValue path (recommended);</li>
 *   <li>{@link #validate(char[], PasswordInputPolicy)} for the legacy
 *       char[] path — the array is <em>not</em> zeroed; the caller
 *       retains ownership.</li>
 * </ul>
 */
public final class PasswordInputValidator {

  public PasswordInputValidator() {
  }

  public PasswordInputValidationResult validate(
      SecretValue secret, PasswordInputPolicy policy) {
    Objects.requireNonNull(secret, "secret");
    Objects.requireNonNull(policy, "policy");
    char[] chars = secret.asChars();
    try {
      return validate(chars, policy);
    } finally {
      java.util.Arrays.fill(chars, '\0');
    }
  }

  public PasswordInputValidationResult validate(
      char[] chars, PasswordInputPolicy policy) {
    Objects.requireNonNull(chars, "chars");
    Objects.requireNonNull(policy, "policy");
    int length = chars.length;
    if (length < policy.minLengthChars()) {
      return new PasswordInputValidationResult.Rejected(
          PasswordInputViolation.TOO_SHORT);
    }
    if (length > policy.maxLengthChars()) {
      return new PasswordInputValidationResult.Rejected(
          PasswordInputViolation.TOO_LONG);
    }
    if (policy.rejectControlCharacters()) {
      for (int i = 0; i < length; i++) {
        if (Character.isISOControl(chars[i])) {
          return new PasswordInputValidationResult.Rejected(
              PasswordInputViolation.CONTAINS_CONTROL_CHARACTER);
        }
      }
    }
    return PasswordInputValidationResult.Accepted.INSTANCE;
  }
}
