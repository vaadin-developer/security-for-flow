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

import eu.jsentinel.jcustos.credential.secret.SecretValue;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

/**
 * Selector/verifier token issuance and verification.
 *
 * <p>A reset-, email-verification- or remember-me token consists of a
 * non-secret <em>selector</em> (looked up in the store) and a secret
 * <em>verifier</em> (compared against the stored digest in constant
 * time). The password-hashing pipeline is deliberately <strong>not</strong>
 * used here: random-salt KDFs cannot be looked up by hash, and using
 * one would either force an O(n) scan or leak timing information
 * (CWE-208 / CWE-640).</p>
 *
 * <p>Verifier digest = SHA-256 of the verifier bytes. The verifier
 * itself comes from {@link SecureRandom} with at least 32 bytes of
 * entropy (CWE-330), so a plain unkeyed digest is unforgeable without
 * the verifier.</p>
 */
public final class TokenDigestService {

  private static final String DIGEST_ALG = "SHA-256";
  /** 16-byte selector → 22-char Base64URL. */
  static final int SELECTOR_BYTES = 16;
  /** 32-byte verifier → 43-char Base64URL. */
  static final int VERIFIER_BYTES = 32;

  private final SecureRandom random;

  public TokenDigestService() {
    this(new SecureRandom());
  }

  public TokenDigestService(SecureRandom random) {
    this.random = Objects.requireNonNull(random, "random");
  }

  /**
   * Generates a fresh token from the supplied {@link SecureRandom}.
   */
  public SelectorVerifierToken generate() {
    byte[] selectorBytes = new byte[SELECTOR_BYTES];
    byte[] verifierBytes = new byte[VERIFIER_BYTES];
    random.nextBytes(selectorBytes);
    random.nextBytes(verifierBytes);
    try {
      String selector = Base64.getUrlEncoder().withoutPadding()
          .encodeToString(selectorBytes);
      String verifierString = Base64.getUrlEncoder().withoutPadding()
          .encodeToString(verifierBytes);
      return new SelectorVerifierToken(
          selector, SecretValue.ofString(verifierString));
    } finally {
      Arrays.fill(selectorBytes, (byte) 0);
      Arrays.fill(verifierBytes, (byte) 0);
    }
  }

  /**
   * Returns the persistable digest record for the supplied token.
   */
  public TokenDigestRecord digest(SelectorVerifierToken token) {
    Objects.requireNonNull(token, "token");
    char[] verifierChars = token.verifier().asChars();
    byte[] verifierBytes = null;
    byte[] digest = null;
    try {
      verifierBytes = utf8(verifierChars);
      digest = sha256(verifierBytes);
      return new TokenDigestRecord(token.selector(), digest);
    } finally {
      Arrays.fill(verifierChars, '\0');
      if (verifierBytes != null) {
        Arrays.fill(verifierBytes, (byte) 0);
      }
      if (digest != null) {
        Arrays.fill(digest, (byte) 0);
      }
    }
  }

  /**
   * Parses the wire form {@code selector.verifier}. Returns
   * {@link Optional#empty()} for malformed input — the caller maps that
   * to the same generic public failure as a wrong verifier so timing
   * stays uniform (CWE-208).
   */
  public Optional<SelectorVerifierToken> parse(String wire) {
    if (wire == null || wire.isEmpty()) {
      return Optional.empty();
    }
    int dot = wire.indexOf('.');
    if (dot <= 0 || dot >= wire.length() - 1) {
      return Optional.empty();
    }
    String selector = wire.substring(0, dot);
    String verifier = wire.substring(dot + 1);
    if (selector.isBlank() || verifier.isBlank()) {
      return Optional.empty();
    }
    return Optional.of(new SelectorVerifierToken(
        selector, SecretValue.ofString(verifier)));
  }

  /**
   * Verifies the supplied token's verifier against the stored digest
   * record. Constant-time comparison via {@link MessageDigest#isEqual}.
   */
  public TokenVerificationResult verifyVerifier(
      SelectorVerifierToken candidate, TokenDigestRecord stored) {
    Objects.requireNonNull(candidate, "candidate");
    Objects.requireNonNull(stored, "stored");
    if (!candidate.selector().equals(stored.selector())) {
      return TokenVerificationResult.SelectorMismatch.INSTANCE;
    }
    char[] verifierChars = candidate.verifier().asChars();
    byte[] verifierBytes = null;
    byte[] candidateDigest = null;
    byte[] storedDigest = stored.copyVerifierDigest();
    try {
      verifierBytes = utf8(verifierChars);
      candidateDigest = sha256(verifierBytes);
      return MessageDigest.isEqual(candidateDigest, storedDigest)
          ? TokenVerificationResult.Verified.INSTANCE
          : TokenVerificationResult.NotMatched.INSTANCE;
    } finally {
      Arrays.fill(verifierChars, '\0');
      Arrays.fill(storedDigest, (byte) 0);
      if (verifierBytes != null) {
        Arrays.fill(verifierBytes, (byte) 0);
      }
      if (candidateDigest != null) {
        Arrays.fill(candidateDigest, (byte) 0);
      }
    }
  }

  private static byte[] utf8(char[] chars) {
    java.nio.CharBuffer cb = java.nio.CharBuffer.wrap(chars);
    java.nio.ByteBuffer bb = java.nio.charset.StandardCharsets.UTF_8.encode(cb);
    byte[] out = new byte[bb.remaining()];
    bb.get(out);
    if (bb.hasArray()) {
      Arrays.fill(bb.array(), bb.arrayOffset(),
          bb.arrayOffset() + bb.capacity(), (byte) 0);
    }
    return out;
  }

  private static byte[] sha256(byte[] input) {
    try {
      MessageDigest md = MessageDigest.getInstance(DIGEST_ALG);
      return md.digest(input);
    } catch (NoSuchAlgorithmException e) {
      // SHA-256 is mandatory in every conformant JCA provider.
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }
}
