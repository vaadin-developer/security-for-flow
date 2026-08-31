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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.text.Normalizer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class PasswordNormalizerTest {

  private final PasswordNormalizer normalizer = new PasswordNormalizer();

  /**
   * Latin small letter "a" with combining diaeresis (NFD) — decomposed
   * form of "ä".
   */
  private static final char[] A_DIAERESIS_DECOMPOSED = {'a', '̈'};
  private static final char[] A_DIAERESIS_PRECOMPOSED = {'ä'};

  @Test
  @DisplayName("NFC normalises a decomposed character to the precomposed form")
  void nfcNormalisesDecomposed() {
    SecretValue input = SecretValue.ofChars(A_DIAERESIS_DECOMPOSED);
    SecretValue normalised = normalizer.normalize(input,
        PasswordInputPolicy.defaults());
    assertArrayEquals(A_DIAERESIS_PRECOMPOSED, normalised.asChars());
  }

  @Test
  @DisplayName("Two Unicode-equivalent representations normalise to the same characters")
  void equivalentRepresentationsAgree() {
    PasswordInputPolicy policy = PasswordInputPolicy.defaults();
    SecretValue a = normalizer.normalize(
        SecretValue.ofChars(A_DIAERESIS_DECOMPOSED), policy);
    SecretValue b = normalizer.normalize(
        SecretValue.ofChars(A_DIAERESIS_PRECOMPOSED), policy);
    assertArrayEquals(a.asChars(), b.asChars(),
        "NFC normalisation must collapse equivalent Unicode representations");
  }

  @Test
  @DisplayName("JS-SEC-047: disabled normalisation copies verbatim into an independent SecretValue and leaves the input intact")
  void disabledNormalisationCopiesVerbatim() {
    PasswordInputPolicy noNorm = new PasswordInputPolicy(
        1, 1024, false, Normalizer.Form.NFC, false);
    SecretValue input = SecretValue.ofChars(A_DIAERESIS_DECOMPOSED);
    SecretValue out = normalizer.normalize(input, noNorm);
    assertArrayEquals(A_DIAERESIS_DECOMPOSED, out.asChars());
    // ofChars copies, so zeroing the pass-through transient (JS-SEC-047) leaves the returned value
    // and the source input untouched — the input must still read back verbatim.
    assertArrayEquals(A_DIAERESIS_DECOMPOSED, input.asChars());
  }

  @Test
  @DisplayName("ASCII input is left unchanged by NFC normalisation")
  void asciiInputUnchanged() {
    SecretValue out = normalizer.normalize(
        SecretValue.ofString("hunter22"), PasswordInputPolicy.defaults());
    assertArrayEquals("hunter22".toCharArray(), out.asChars());
  }

  @Test
  @DisplayName("NFC and NFD policies produce different outputs for a precomposed input")
  void nfcVersusNfd() {
    PasswordInputPolicy nfd = new PasswordInputPolicy(
        1, 1024, true, Normalizer.Form.NFD, false);
    SecretValue out = normalizer.normalize(
        SecretValue.ofChars(A_DIAERESIS_PRECOMPOSED), nfd);
    assertEquals(2, out.length(), "NFD must decompose ä into a + combining mark");
    assertNotEquals('ä', out.asChars()[0]);
  }

  @Test
  @DisplayName("normalize returns a fresh SecretValue each call")
  void normalizeReturnsFreshSecret() {
    SecretValue input = SecretValue.ofString("hunter22");
    SecretValue first = normalizer.normalize(input, PasswordInputPolicy.defaults());
    SecretValue second = normalizer.normalize(input, PasswordInputPolicy.defaults());
    assertArrayEquals(first.asChars(), second.asChars());
    first.destroy();
    // destroying the first must not affect the second
    assertArrayEquals("hunter22".toCharArray(), second.asChars());
  }
}
