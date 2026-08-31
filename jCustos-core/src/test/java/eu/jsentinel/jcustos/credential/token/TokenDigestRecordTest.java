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
package eu.jsentinel.jcustos.credential.token;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenDigestRecordTest {

  private static final byte[] DIGEST_A = new byte[] {1, 2, 3, 4, 5};
  private static final byte[] DIGEST_B = new byte[] {9, 8, 7, 6, 5};

  @Test
  @DisplayName("Constructor rejects null selector / digest")
  void constructorRejectsNull() {
    assertThrows(NullPointerException.class,
        () -> new TokenDigestRecord(null, DIGEST_A));
    assertThrows(NullPointerException.class,
        () -> new TokenDigestRecord("sel", null));
  }

  @Test
  @DisplayName("Constructor rejects blank selector / empty digest")
  void constructorRejectsBlankOrEmpty() {
    assertThrows(IllegalArgumentException.class,
        () -> new TokenDigestRecord(" ", DIGEST_A));
    assertThrows(IllegalArgumentException.class,
        () -> new TokenDigestRecord("sel", new byte[0]));
  }

  @Test
  @DisplayName("Constructor defensively copies the digest array")
  void constructorClonesDigest() {
    byte[] source = DIGEST_A.clone();
    TokenDigestRecord r = new TokenDigestRecord("sel", source);
    // mutate the source — the record's view must be unaffected
    source[0] = 99;
    byte[] inside = r.copyVerifierDigest();
    assertEquals(1, inside[0],
        "constructor must clone, not capture by reference");
  }

  @Test
  @DisplayName("copyVerifierDigest returns a fresh array every time")
  void copyReturnsFresh() {
    TokenDigestRecord r = new TokenDigestRecord("sel", DIGEST_A);
    byte[] a = r.copyVerifierDigest();
    byte[] b = r.copyVerifierDigest();
    assertNotSame(a, b);
    assertEquals(a[0], b[0]);
    // mutating one copy must not affect another
    a[0] = 77;
    assertNotEquals(a[0], b[0]);
  }

  @Test
  @DisplayName("equals: self-equality (this == o branch)")
  void equalsSelf() {
    TokenDigestRecord r = new TokenDigestRecord("sel", DIGEST_A);
    assertTrue(r.equals(r));
  }

  @Test
  @DisplayName("equals: same selector + digest → true")
  void equalsSameContent() {
    TokenDigestRecord a = new TokenDigestRecord("sel", DIGEST_A);
    TokenDigestRecord b = new TokenDigestRecord("sel", DIGEST_A.clone());
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  @DisplayName("equals: different selector → false")
  void equalsDifferentSelector() {
    TokenDigestRecord a = new TokenDigestRecord("sel-A", DIGEST_A);
    TokenDigestRecord b = new TokenDigestRecord("sel-B", DIGEST_A.clone());
    assertNotEquals(a, b);
  }

  @Test
  @DisplayName("equals: same selector, different digest → false")
  void equalsDifferentDigest() {
    TokenDigestRecord a = new TokenDigestRecord("sel", DIGEST_A);
    TokenDigestRecord b = new TokenDigestRecord("sel", DIGEST_B);
    assertNotEquals(a, b);
  }

  @Test
  @DisplayName("equals: foreign type → false")
  void equalsForeignType() {
    TokenDigestRecord r = new TokenDigestRecord("sel", DIGEST_A);
    assertFalse(r.equals("sel"));
    assertFalse(r.equals(null));
  }

  @Test
  @DisplayName("hashCode mixes selector + digest")
  void hashCodeMixesBoth() {
    TokenDigestRecord same1 = new TokenDigestRecord("sel", DIGEST_A);
    TokenDigestRecord same2 = new TokenDigestRecord("sel", DIGEST_A.clone());
    assertEquals(same1.hashCode(), same2.hashCode());

    TokenDigestRecord otherSelector = new TokenDigestRecord("sel2", DIGEST_A);
    assertNotEquals(same1.hashCode(), otherSelector.hashCode());

    TokenDigestRecord otherDigest = new TokenDigestRecord("sel", DIGEST_B);
    assertNotEquals(same1.hashCode(), otherDigest.hashCode());
  }

  @Test
  @DisplayName("toString includes selector + length but never the digest bytes")
  void toStringRedacts() {
    TokenDigestRecord r = new TokenDigestRecord("sel-X", DIGEST_A);
    String text = r.toString();
    assertTrue(text.contains("selector=sel-X"));
    assertTrue(text.contains("digestLength=" + DIGEST_A.length));
    assertTrue(text.contains("<redacted>"));
    // no raw bytes leaked
    assertFalse(text.contains("[1, 2, 3"));
  }
}
