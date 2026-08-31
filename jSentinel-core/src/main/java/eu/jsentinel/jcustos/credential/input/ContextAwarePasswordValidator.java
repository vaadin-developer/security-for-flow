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

import java.util.Arrays;
import java.util.Objects;

/**
 * Context-aware password validator that wraps the structural
 * {@link PasswordInputValidator} with the checks the Konzept §14
 * mandates: a password must not contain its user's username, the
 * local part of their email, the email domain, or any of the
 * operator-supplied forbidden terms (CWE-521 / CWE-287).
 *
 * <h2>No composition rules</h2>
 * <p>Modern password guidance (NIST SP 800-63B) advises against
 * <em>composition rules</em> ("must contain a symbol", "must contain
 * a number"). This validator therefore <strong>does not</strong>
 * enforce composition; it relies on the configured
 * {@link PasswordInputPolicy} length window plus context-aware
 * rejection of brittle reused tokens. Operators who want strict
 * composition rules layer their own validator on top.</p>
 *
 * <p>All substring checks are case-insensitive. Comparison uses
 * {@link String#toLowerCase()} on copies of the borrowed
 * {@code char[]} that the validator zeroes in a {@code finally}
 * block (CWE-226).</p>
 */
public final class ContextAwarePasswordValidator {

  private final PasswordInputValidator structural;

  public ContextAwarePasswordValidator() {
    this(new PasswordInputValidator());
  }

  public ContextAwarePasswordValidator(PasswordInputValidator structural) {
    this.structural = Objects.requireNonNull(structural, "structural");
  }

  /**
   * Runs both the structural and context-aware checks. The first
   * violation wins; subsequent checks are not consulted.
   */
  public PasswordInputValidationResult validate(
      SecretValue secret,
      PasswordInputPolicy policy,
      PasswordContext context) {
    Objects.requireNonNull(secret, "secret");
    Objects.requireNonNull(policy, "policy");
    Objects.requireNonNull(context, "context");

    PasswordInputValidationResult structuralResult =
        structural.validate(secret, policy);
    if (structuralResult instanceof PasswordInputValidationResult.Rejected) {
      return structuralResult;
    }

    char[] chars = secret.asChars();
    try {
      String lowered = new String(chars).toLowerCase();
      if (containsCaseInsensitive(lowered, context.username())) {
        return new PasswordInputValidationResult.Rejected(
            PasswordInputViolation.CONTAINS_USERNAME);
      }
      if (context.emailLocalPart().isPresent()
          && containsCaseInsensitive(lowered, context.emailLocalPart().get())) {
        return new PasswordInputValidationResult.Rejected(
            PasswordInputViolation.CONTAINS_EMAIL_LOCAL_PART);
      }
      if (context.emailDomain().isPresent()
          && containsCaseInsensitive(lowered, context.emailDomain().get())) {
        return new PasswordInputValidationResult.Rejected(
            PasswordInputViolation.CONTAINS_EMAIL_DOMAIN);
      }
      for (String term : context.forbiddenTerms()) {
        if (containsCaseInsensitive(lowered, term)) {
          return new PasswordInputValidationResult.Rejected(
              PasswordInputViolation.CONTAINS_FORBIDDEN_TERM);
        }
      }
      return PasswordInputValidationResult.Accepted.INSTANCE;
    } finally {
      Arrays.fill(chars, '\0');
    }
  }

  private static boolean containsCaseInsensitive(
      String passwordLower, String needle) {
    if (needle == null || needle.isBlank()) {
      return false;
    }
    return passwordLower.contains(needle.toLowerCase());
  }
}
