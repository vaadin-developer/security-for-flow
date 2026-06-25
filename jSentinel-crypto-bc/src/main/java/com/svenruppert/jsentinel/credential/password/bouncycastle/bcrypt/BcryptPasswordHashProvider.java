/*-
 * #%L
 * Security Crypto — BouncyCastle
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
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
package com.svenruppert.jsentinel.credential.password.bouncycastle.bcrypt;

import com.svenruppert.jsentinel.credential.CredentialType;
import com.svenruppert.jsentinel.credential.InternalAuditEventType;
import com.svenruppert.jsentinel.credential.password.PasswordHashResult;
import com.svenruppert.jsentinel.credential.password.ProviderVerificationResult;
import com.svenruppert.jsentinel.credential.password.envelope.PasswordHashCodec;
import com.svenruppert.jsentinel.credential.password.envelope.PasswordHashEnvelope;
import com.svenruppert.jsentinel.credential.password.pepper.PepperApplicator;
import com.svenruppert.jsentinel.credential.password.pepper.PepperReference;
import com.svenruppert.jsentinel.credential.password.policy.PasswordHashPolicy;
import com.svenruppert.jsentinel.credential.password.provider.PasswordHashProvider;
import org.bouncycastle.crypto.generators.BCrypt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * bcrypt password hash provider backed by BouncyCastle's low-level
 * {@link BCrypt} generator (Bcprov's lightweight API, no JCA
 * registration).
 *
 * <h2>72-byte input limit</h2>
 * <p>bcrypt's underlying Blowfish key schedule operates on a fixed
 * 72-byte input. Passwords longer than 72&nbsp;bytes in their UTF-8
 * encoding are <em>not</em> silently truncated by this provider; they
 * are rejected with a
 * {@link ProviderVerificationResult.ProviderError}. The Konzept
 * §2.2 also forbids silent pre-hashing without a real pepper service,
 * so callers must enforce a policy-level length cap or wait for the
 * Phase-2 pepper-HMAC integration (Prompt 017).</p>
 *
 * <h2>Password shucking</h2>
 * <p>Pre-hashing a password before handing it to bcrypt without a
 * site-wide secret (pepper) lets attackers shuck the outer hash. This
 * provider therefore stays a plain bcrypt implementation in Phase 1b;
 * pre-hashing arrives bundled with the real pepper service in Phase 2.
 * (See §11 of the V9 Konzept.)</p>
 */
public final class BcryptPasswordHashProvider implements PasswordHashProvider {

  private final PasswordHashCodec codec;
  private final SecureRandom random;

  public BcryptPasswordHashProvider() {
    this(PasswordHashCodec.DEFAULT, new SecureRandom());
  }

  public BcryptPasswordHashProvider(
      PasswordHashCodec codec, SecureRandom random) {
    this.codec = Objects.requireNonNull(codec, "codec");
    this.random = Objects.requireNonNull(random, "random");
  }

  @Override
  public String providerId() {
    return BcryptParameterNames.PROVIDER_ID;
  }

  @Override
  public String algorithm() {
    return BcryptParameterNames.ALGORITHM;
  }

  @Override
  public PasswordHashResult hash(
      char[] password,
      PasswordHashPolicy policy,
      Optional<PepperReference> pepper) {
    Objects.requireNonNull(password, "password");
    Objects.requireNonNull(policy, "policy");
    Objects.requireNonNull(pepper, "pepper");

    byte[] pwBytes = toUtf8(password);
    try {
      requireUnderBcryptLimit(pwBytes);
      Map<String, String> defaults = policy.defaultParameters(algorithm());
      int cost = intOrDefault(defaults, BcryptParameterNames.COST,
          BcryptDefaults.DEFAULT_COST);

      byte[] salt = new byte[BcryptParameterNames.SALT_BYTES];
      random.nextBytes(salt);
      byte[] derived = null;
      byte[] peppered = null;
      try {
        derived = BCrypt.generate(pwBytes, salt, cost);
        peppered = PepperApplicator.apply(derived, pepper);
        Map<String, String> params = new LinkedHashMap<>();
        params.put(BcryptParameterNames.COST, Integer.toString(cost));
        params.put(BcryptParameterNames.SALT,
            Base64.getEncoder().encodeToString(salt));
        Optional<String> pepperKeyId = pepper.map(PepperReference::keyId);

        PasswordHashEnvelope envelope = new PasswordHashEnvelope(
            policy.preferredFormatVersion(),
            CredentialType.PASSWORD,
            algorithm(),
            providerId(),
            policy.policyVersion(),
            pepperKeyId,
            params,
            Base64.getEncoder().encodeToString(peppered));
        String encoded = codec.encode(envelope);

        return new PasswordHashResult(
            encoded,
            CredentialType.PASSWORD,
            envelope.formatVersion().wireValue(),
            algorithm(),
            providerId(),
            policy.policyVersion(),
            pepperKeyId,
            params);
      } finally {
        Arrays.fill(salt, (byte) 0);
        if (derived != null) {
          Arrays.fill(derived, (byte) 0);
        }
        if (peppered != null) {
          Arrays.fill(peppered, (byte) 0);
        }
      }
    } finally {
      Arrays.fill(pwBytes, (byte) 0);
    }
  }

  @Override
  public ProviderVerificationResult verify(
      char[] password,
      PasswordHashEnvelope envelope,
      Optional<PepperReference> pepper) {
    Objects.requireNonNull(password, "password");
    Objects.requireNonNull(envelope, "envelope");
    Objects.requireNonNull(pepper, "pepper");

    Map<String, String> params = envelope.parameters();
    int cost;
    byte[] salt;
    byte[] expectedDerived;
    try {
      cost = Integer.parseInt(
          Objects.requireNonNull(params.get(BcryptParameterNames.COST)));
      salt = Base64.getDecoder().decode(
          Objects.requireNonNull(params.get(BcryptParameterNames.SALT)));
      expectedDerived = Base64.getDecoder().decode(envelope.innerHash());
    } catch (NullPointerException | IllegalArgumentException e) {
      return new ProviderVerificationResult.ProviderError(
          InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
          "bcrypt envelope parameters are not parseable");
    }
    if (salt.length != BcryptParameterNames.SALT_BYTES) {
      Arrays.fill(salt, (byte) 0);
      return new ProviderVerificationResult.ProviderError(
          InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
          "bcrypt salt has unexpected length");
    }
    if (cost > BcryptDefaults.MAX_COST) {
      // R02: defence-in-depth — reject a cost above the hard ceiling BEFORE
      // computing. bcrypt runs 2^cost key-schedule rounds, so a tampered envelope
      // with cost=31 would monopolise a worker thread for an extreme duration
      // (CWE-400/770). The policy-driven validator only runs on the hash path,
      // not here. Mirrors the scrypt/argon2 R017 verify guards. The lower bound
      // is intentionally NOT enforced: a legitimately weaker legacy hash must
      // still verify (and then trigger a rehash) — and an out-of-range low/high
      // cost outside bcrypt's 4..31 range is already caught by the generator.
      Arrays.fill(salt, (byte) 0);
      return new ProviderVerificationResult.ProviderError(
          InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
          "bcrypt envelope cost parameters exceed safe limits");
    }

    byte[] pwBytes = toUtf8(password);
    byte[] candidate = null;
    byte[] peppered = null;
    try {
      if (pwBytes.length > BcryptParameterNames.MAX_PASSWORD_BYTES) {
        return new ProviderVerificationResult.ProviderError(
            InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
            "candidate password exceeds bcrypt 72-byte input limit");
      }
      try {
        candidate = BCrypt.generate(pwBytes, salt, cost);
      } catch (RuntimeException e) {
        return new ProviderVerificationResult.ProviderError(
            InternalAuditEventType.VERIFICATION_FAILED_PROVIDER_ERROR,
            "bcrypt generator rejected the parameters");
      }
      try {
        peppered = PepperApplicator.apply(candidate, pepper);
      } catch (PepperApplicator.PepperApplicationException e) {
        return new ProviderVerificationResult.ProviderError(
            InternalAuditEventType.VERIFICATION_FAILED_PROVIDER_ERROR,
            e.getMessage());
      }
      return MessageDigest.isEqual(peppered, expectedDerived)
          ? ProviderVerificationResult.Matched.INSTANCE
          : ProviderVerificationResult.NotMatched.INSTANCE;
    } finally {
      Arrays.fill(pwBytes, (byte) 0);
      Arrays.fill(salt, (byte) 0);
      Arrays.fill(expectedDerived, (byte) 0);
      if (candidate != null) {
        Arrays.fill(candidate, (byte) 0);
      }
      if (peppered != null) {
        Arrays.fill(peppered, (byte) 0);
      }
    }
  }

  private static void requireUnderBcryptLimit(byte[] pwBytes) {
    if (pwBytes.length > BcryptParameterNames.MAX_PASSWORD_BYTES) {
      throw new BcryptInputTooLongException();
    }
  }

  private static byte[] toUtf8(char[] password) {
    java.nio.CharBuffer charBuffer = java.nio.CharBuffer.wrap(password);
    java.nio.ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(charBuffer);
    byte[] out = new byte[byteBuffer.remaining()];
    byteBuffer.get(out);
    if (byteBuffer.hasArray()) {
      Arrays.fill(byteBuffer.array(), (byte) 0);
    }
    return out;
  }

  private static int intOrDefault(
      Map<String, String> map, String key, int fallback) {
    String raw = map.get(key);
    if (raw == null) {
      return fallback;
    }
    try {
      return Integer.parseInt(raw);
    } catch (NumberFormatException e) {
      return fallback;
    }
  }

  /**
   * Control-flow signal that the supplied password exceeds bcrypt's
   * fixed 72-byte UTF-8 input limit. Surfaced to callers of
   * {@link #hash(char[], PasswordHashPolicy, java.util.Optional)} so
   * the bootstrap or registration path can reject overlong passwords
   * up front instead of silently truncating them.
   */
  public static final class BcryptInputTooLongException extends RuntimeException {
    public BcryptInputTooLongException() {
      super("password exceeds bcrypt 72-byte input limit");
    }
  }
}
