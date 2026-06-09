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
package com.svenruppert.jsentinel.credential.input;

import com.svenruppert.jsentinel.credential.secret.SecretValue;

import java.nio.CharBuffer;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.Objects;

/**
 * Normalises password material under the active
 * {@link PasswordInputPolicy} so that two equivalent Unicode
 * representations of the same characters compare equal across
 * hash/verify (CWE-176).
 *
 * <h2>JVM memory honesty</h2>
 * <p>The JDK's {@link Normalizer#normalize(CharSequence, Normalizer.Form)}
 * returns a {@link String}. {@code String} instances are immutable and
 * may be retained by the JVM. The normalizer copies that String into a
 * fresh {@link SecretValue} and discards the reference, but a brief
 * window remains where the normalised material lives in a String
 * object. This is the same caveat documented on {@link SecretValue};
 * see CWE-226.</p>
 *
 * <p>Pre-hashing of overlong inputs is intentionally not performed
 * here. The Konzept §11 forbids silent pre-hashing without a real
 * pepper service (password shucking risk); the bcrypt provider rejects
 * overlong inputs explicitly.</p>
 */
public final class PasswordNormalizer {

  public PasswordNormalizer() {
  }

  /**
   * Returns a new {@link SecretValue} containing the normalised form.
   * The input is left intact (callers are usually mid-pipeline and
   * close their own secret in a try-with-resources block).
   */
  public SecretValue normalize(SecretValue input, PasswordInputPolicy policy) {
    Objects.requireNonNull(input, "input");
    Objects.requireNonNull(policy, "policy");
    if (!policy.unicodeNormalisationEnabled()) {
      return SecretValue.ofChars(input.asChars());
    }
    char[] chars = input.asChars();
    char[] normalisedChars = null;
    try {
      CharBuffer wrapped = CharBuffer.wrap(chars);
      String normalised = Normalizer.normalize(wrapped, policy.normalisationForm());
      normalisedChars = normalised.toCharArray();
      return SecretValue.ofChars(normalisedChars);
    } finally {
      Arrays.fill(chars, '\0');
      if (normalisedChars != null) {
        Arrays.fill(normalisedChars, '\0');
      }
    }
  }
}
