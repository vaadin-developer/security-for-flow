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
package eu.jsentinel.jcustos.credential.token;

import eu.jsentinel.jcustos.credential.secret.SecretValue;

import java.util.Objects;

/**
 * Two-part token used for password-reset, email-verification and
 * remember-me flows.
 *
 * <p>The {@code selector} is a non-secret lookup key persisted next to
 * the digest of the verifier; it lets the store find the right record
 * in O(1) without scanning. The {@code verifier} is the secret half
 * — exposed only on the wire while the user clicks the link and held
 * in a {@link SecretValue} otherwise so {@link #toString()} can never
 * leak it (CWE-522 / CWE-209).</p>
 *
 * <p>The wire format is {@code selector.verifier} (both Base64URL
 * without padding). {@link TokenDigestService#parse(String)} performs
 * the inverse.</p>
 */
public record SelectorVerifierToken(String selector, SecretValue verifier) {

  public SelectorVerifierToken {
    Objects.requireNonNull(selector, "selector");
    if (selector.isBlank()) {
      throw new IllegalArgumentException("selector must not be blank");
    }
    Objects.requireNonNull(verifier, "verifier");
  }

  /**
   * Returns the wire form {@code selector.verifier}. The caller is
   * responsible for zeroing the returned {@link CharSequence}-derived
   * string after use.
   */
  public String encode() {
    char[] verifierChars = verifier.asChars();
    try {
      return selector + "." + new String(verifierChars);
    } finally {
      java.util.Arrays.fill(verifierChars, '\0');
    }
  }

  @Override
  public String toString() {
    return "SelectorVerifierToken[selector=" + selector + ", verifier=<redacted>]";
  }
}
