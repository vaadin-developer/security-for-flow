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
package com.svenruppert.vaadin.security.credential.input;

import java.text.Normalizer;
import java.util.Objects;

/**
 * Operator-configurable input hygiene rules for password material.
 *
 * <p>Length bounds keep callers safe against overlong-input abuse
 * (CWE-400). The Unicode normalisation flag controls whether passwords
 * are normalised to a canonical form before hashing — if enabled, the
 * same normalisation runs on hash <em>and</em> verify so two
 * representations of the same characters still match (CWE-176).</p>
 *
 * <p>Pre-hashing of overlong inputs is intentionally absent: silent
 * pre-hashing without a real pepper service makes credentials shuckable
 * (see Konzept §11 and Prompt 011). The bcrypt provider therefore
 * rejects overlong inputs explicitly; the {@code maxLengthChars} guard
 * here serves the other algorithms too.</p>
 *
 * @param minLengthChars              minimum number of Java characters
 *                                    (default 8); 0 means "no minimum"
 * @param maxLengthChars              maximum number of Java characters
 *                                    (default 1024); guards against
 *                                    pathological inputs
 * @param unicodeNormalisationEnabled whether the normalizer runs at all
 *                                    (default {@code true})
 * @param normalisationForm           which Unicode form to use; only
 *                                    consulted when normalisation is
 *                                    enabled
 * @param rejectControlCharacters     whether
 *                                    {@link Character#isISOControl(int)}
 *                                    code points are rejected (default
 *                                    {@code false} so newline/tab inside
 *                                    a passphrase remain legal)
 */
public record PasswordInputPolicy(
    int minLengthChars,
    int maxLengthChars,
    boolean unicodeNormalisationEnabled,
    Normalizer.Form normalisationForm,
    boolean rejectControlCharacters
) {

  public PasswordInputPolicy {
    if (minLengthChars < 0) {
      throw new IllegalArgumentException("minLengthChars must be >= 0");
    }
    if (maxLengthChars < 1) {
      throw new IllegalArgumentException("maxLengthChars must be >= 1");
    }
    if (minLengthChars > maxLengthChars) {
      throw new IllegalArgumentException(
          "minLengthChars must be <= maxLengthChars");
    }
    Objects.requireNonNull(normalisationForm, "normalisationForm");
  }

  /**
   * OWASP-2023 baseline: 8..1024 characters, NFC normalisation on,
   * control characters allowed.
   */
  public static PasswordInputPolicy defaults() {
    return new PasswordInputPolicy(
        8, 1024, true, Normalizer.Form.NFC, false);
  }
}
