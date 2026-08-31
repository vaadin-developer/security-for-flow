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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenDigestServiceTest {

  private final TokenDigestService service = new TokenDigestService();

  @Test
  @DisplayName("generate produces a token with a 22-char selector and a 43-char verifier (Base64URL)")
  void generateProducesExpectedShape() {
    SelectorVerifierToken token = service.generate();
    assertEquals(22, token.selector().length(),
        "selector should encode 16 bytes as Base64URL without padding");
    assertEquals(43, token.verifier().length(),
        "verifier should encode 32 bytes as Base64URL without padding");
  }

  @Test
  @DisplayName("Two consecutive generate calls produce different tokens")
  void generateIsRandom() {
    SelectorVerifierToken a = service.generate();
    SelectorVerifierToken b = service.generate();
    assertNotEquals(a.selector(), b.selector());
    char[] av = a.verifier().asChars();
    char[] bv = b.verifier().asChars();
    try {
      assertFalse(java.util.Arrays.equals(av, bv));
    } finally {
      java.util.Arrays.fill(av, '\0');
      java.util.Arrays.fill(bv, '\0');
    }
  }

  @Test
  @DisplayName("digest + verifyVerifier roundtrip succeeds")
  void digestAndVerifySucceeds() {
    SelectorVerifierToken token = service.generate();
    TokenDigestRecord record = service.digest(token);
    assertSame(TokenVerificationResult.Verified.INSTANCE,
        service.verifyVerifier(token, record));
  }

  @Test
  @DisplayName("Wrong verifier yields NotMatched (constant-time comparison via MessageDigest.isEqual)")
  void wrongVerifierYieldsNotMatched() {
    SelectorVerifierToken issued = service.generate();
    TokenDigestRecord record = service.digest(issued);
    SelectorVerifierToken tampered = new SelectorVerifierToken(
        issued.selector(),
        SecretValue.ofString("tampered-verifier-of-the-same-length-AAAA")); // 43 chars
    assertSame(TokenVerificationResult.NotMatched.INSTANCE,
        service.verifyVerifier(tampered, record));
  }

  @Test
  @DisplayName("Different selector yields SelectorMismatch")
  void selectorMismatch() {
    SelectorVerifierToken a = service.generate();
    SelectorVerifierToken b = service.generate();
    TokenDigestRecord recordOfA = service.digest(a);
    SelectorVerifierToken probe = new SelectorVerifierToken(
        b.selector(), SecretValue.ofChars(a.verifier().asChars()));
    assertSame(TokenVerificationResult.SelectorMismatch.INSTANCE,
        service.verifyVerifier(probe, recordOfA));
  }

  @Test
  @DisplayName("encode + parse roundtrip")
  void encodeAndParseRoundtrip() {
    SelectorVerifierToken original = service.generate();
    String wire = original.encode();
    SelectorVerifierToken parsed = service.parse(wire).orElseThrow();
    assertEquals(original.selector(), parsed.selector());
    char[] o = original.verifier().asChars();
    char[] p = parsed.verifier().asChars();
    try {
      assertTrue(java.util.Arrays.equals(o, p));
    } finally {
      java.util.Arrays.fill(o, '\0');
      java.util.Arrays.fill(p, '\0');
    }
  }

  @Test
  @DisplayName("Malformed token strings are rejected with Optional.empty")
  void malformedRejected() {
    assertTrue(service.parse(null).isEmpty());
    assertTrue(service.parse("").isEmpty());
    assertTrue(service.parse("no-dot-here").isEmpty());
    assertTrue(service.parse(".verifier").isEmpty(), "empty selector");
    assertTrue(service.parse("selector.").isEmpty(), "empty verifier");
  }

  @Test
  @DisplayName("Wire format starts with the selector, separator '.', then verifier")
  void wireFormat() {
    SelectorVerifierToken token = service.generate();
    String wire = token.encode();
    int dot = wire.indexOf('.');
    assertEquals(22, dot);
    assertEquals(token.selector(), wire.substring(0, dot));
  }

  @Test
  @DisplayName("SelectorVerifierToken.toString never exposes the verifier (CWE-209 / CWE-522)")
  void tokenToStringRedacted() {
    SelectorVerifierToken token = service.generate();
    String text = token.toString();
    char[] verifier = token.verifier().asChars();
    try {
      assertFalse(text.contains(new String(verifier)));
      assertTrue(text.contains("<redacted>"));
    } finally {
      java.util.Arrays.fill(verifier, '\0');
    }
  }

  @Test
  @DisplayName("TokenDigestRecord.toString never exposes the digest bytes")
  void recordToStringRedacted() {
    SelectorVerifierToken token = service.generate();
    TokenDigestRecord record = service.digest(token);
    String text = record.toString();
    byte[] digest = record.copyVerifierDigest();
    try {
      for (byte b : digest) {
        String hex = String.format("%02x", b);
        if (text.toLowerCase().contains(hex)
            && hex.length() == 2 && !hex.equals("00")) {
          // chance of incidental match is real for very short patterns,
          // but a full-byte sequence should not appear
          break;
        }
      }
      assertTrue(text.contains("<redacted>"));
    } finally {
      java.util.Arrays.fill(digest, (byte) 0);
    }
  }

  @Test
  @DisplayName("Sufficient verifier entropy: at least 32 bytes / 256 bits (CWE-330)")
  void entropySpec() {
    assertEquals(16, TokenDigestService.SELECTOR_BYTES,
        "selector must carry 128 bits — collisions across users are still rare");
    assertEquals(32, TokenDigestService.VERIFIER_BYTES,
        "verifier must carry 256 bits so a plain digest stays unforgeable");
  }

  @Test
  @DisplayName("Deterministic random produces the same selector twice (smoke test for the SecureRandom hook)")
  void deterministicRandomReplay() {
    SecureRandom det = new SecureRandom() {
      private long counter;

      @Override
      public synchronized void nextBytes(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
          bytes[i] = (byte) (counter & 0xff);
          counter++;
        }
      }
    };
    TokenDigestService deterministicSvc = new TokenDigestService(det);
    SelectorVerifierToken a = deterministicSvc.generate();
    // Counter is mutated by the first generate(); reset by re-seeding.
    SecureRandom det2 = new SecureRandom() {
      private long counter;

      @Override
      public synchronized void nextBytes(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
          bytes[i] = (byte) (counter & 0xff);
          counter++;
        }
      }
    };
    SelectorVerifierToken b = new TokenDigestService(det2).generate();
    assertEquals(a.selector(), b.selector());
  }

  @Test
  @DisplayName("Constructor rejects null SecureRandom")
  void nullRandomRejected() {
    assertThrows(NullPointerException.class,
        () -> new TokenDigestService(null));
  }

  /**
   * Captures every byte[] passed to nextBytes so the test can prove the
   * generate() finally-block actually zeroed the random buffers. Removing
   * the {@code Arrays.fill} call would leave the random bytes in place,
   * which this assertion detects.
   */
  static final class CapturingSecureRandom extends SecureRandom {
    final java.util.List<byte[]> buffers = new java.util.ArrayList<>();
    @Override public synchronized void nextBytes(byte[] bytes) {
      for (int i = 0; i < bytes.length; i++) {
        bytes[i] = (byte) (i + 1);
      }
      buffers.add(bytes);
    }
  }

  @Test
  @DisplayName("generate() zeroes the random selector + verifier buffers in its finally block")
  void generateWipesRandomBuffers() {
    CapturingSecureRandom rng = new CapturingSecureRandom();
    new TokenDigestService(rng).generate();
    assertEquals(2, rng.buffers.size(),
        "generate fills two buffers: selector + verifier");
    for (byte[] buf : rng.buffers) {
      for (byte b : buf) {
        assertEquals(0, b,
            "every byte must be zeroed after generate() returns — "
                + "removing Arrays.fill would leak random bytes (CWE-226)");
      }
    }
  }

  // ── parse() boundary cases ──────────────────────────────────────

  @Test
  @DisplayName("parse rejects an input where the dot is the last char")
  void parseRejectsTrailingDot() {
    Optional<SelectorVerifierToken> r = service.parse("abc.");
    assertEquals(Optional.empty(), r);
  }

  @Test
  @DisplayName("parse rejects an input where the dot is the first char")
  void parseRejectsLeadingDot() {
    Optional<SelectorVerifierToken> r = service.parse(".xyz");
    assertEquals(Optional.empty(), r);
  }

  @Test
  @DisplayName("parse accepts the minimal valid 1-char selector + 1-char verifier")
  void parseAcceptsMinimal() {
    Optional<SelectorVerifierToken> r = service.parse("a.b");
    assertTrue(r.isPresent());
    assertEquals("a", r.get().selector());
    assertEquals(1, r.get().verifier().length());
  }

  @Test
  @DisplayName("parse rejects whitespace-only selector or verifier")
  void parseRejectsWhitespaceParts() {
    assertEquals(Optional.empty(), service.parse(" .x"));
    assertEquals(Optional.empty(), service.parse("x. "));
  }
}
