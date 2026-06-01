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
package com.svenruppert.vaadin.security.credential.password.pbkdf2;

import com.svenruppert.vaadin.security.credential.CredentialType;
import com.svenruppert.vaadin.security.credential.InternalAuditEventType;
import com.svenruppert.vaadin.security.credential.password.PasswordHashResult;
import com.svenruppert.vaadin.security.credential.password.ProviderVerificationResult;
import com.svenruppert.vaadin.security.credential.password.envelope.PasswordHashCodec;
import com.svenruppert.vaadin.security.credential.password.envelope.PasswordHashEnvelope;
import com.svenruppert.vaadin.security.credential.password.policy.PasswordHashPolicy;
import com.svenruppert.vaadin.security.credential.password.provider.PasswordHashProvider;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * JDK/JCA-only PBKDF2 password hash provider.
 *
 * <p>This is the secure core default and must remain JDK-only so that
 * {@code security-core} introduces no runtime dependencies. Modern
 * memory-hard algorithms (Argon2id, scrypt) live in the optional
 * {@code security-crypto-bc} module that ships in Phase 1b.</p>
 *
 * <p>Implementation notes:</p>
 * <ul>
 *   <li>The provider never modifies the global JCA provider order.
 *       A specific JCA provider can be pinned through the
 *       {@code jcaProviderName} constructor argument; the lookup is
 *       performed via {@link SecretKeyFactory#getInstance(String, String)}
 *       on every call.</li>
 *   <li>Salt is drawn fresh from a caller-supplied
 *       {@link SecureRandom} for every {@code hash(...)} so that two
 *       identical passwords never yield identical envelopes
 *       (CWE-759 / CWE-760).</li>
 *   <li>The constant-time comparison uses
 *       {@link MessageDigest#isEqual(byte[], byte[])}.</li>
 *   <li>Temporary {@code byte[]} arrays holding salt and derived key
 *       material are zeroed before the method returns. The
 *       {@link PBEKeySpec#clearPassword()} hook is invoked even on
 *       failure paths.</li>
 *   <li>The provider returns
 *       {@link ProviderVerificationResult.ProviderError} on JCA-level
 *       failures (missing algorithm or provider, invalid key spec) so
 *       the surrounding pipeline can keep public messaging generic
 *       (CWE-209).</li>
 * </ul>
 */
public final class Pbkdf2PasswordHashProvider implements PasswordHashProvider {

  private final PasswordHashCodec codec;
  private final SecureRandom random;
  private final Optional<String> jcaProviderName;

  public Pbkdf2PasswordHashProvider() {
    this(PasswordHashCodec.DEFAULT, new SecureRandom(), Optional.empty());
  }

  public Pbkdf2PasswordHashProvider(String jcaProviderName) {
    this(PasswordHashCodec.DEFAULT,
        new SecureRandom(),
        Optional.of(Objects.requireNonNull(jcaProviderName, "jcaProviderName")));
  }

  /**
   * Test/SPI constructor that lets callers inject a deterministic
   * {@link SecureRandom} (for known-answer assertions) or pin the JCA
   * provider (for FIPS-mode deployments).
   */
  public Pbkdf2PasswordHashProvider(
      PasswordHashCodec codec,
      SecureRandom random,
      Optional<String> jcaProviderName) {
    this.codec = Objects.requireNonNull(codec, "codec");
    this.random = Objects.requireNonNull(random, "random");
    this.jcaProviderName = Objects.requireNonNull(
        jcaProviderName, "jcaProviderName");
  }

  @Override
  public String providerId() {
    return Pbkdf2ParameterNames.PROVIDER_ID;
  }

  @Override
  public String algorithm() {
    return Pbkdf2ParameterNames.ALGORITHM;
  }

  @Override
  public PasswordHashResult hash(
      char[] password,
      PasswordHashPolicy policy,
      Optional<byte[]> pepperSecret) {
    Objects.requireNonNull(password, "password");
    Objects.requireNonNull(policy, "policy");
    Objects.requireNonNull(pepperSecret, "pepperSecret");

    Map<String, String> defaults = policy.defaultParameters(algorithm());
    int iterations = intOrDefault(defaults, Pbkdf2ParameterNames.ITERATIONS,
        Pbkdf2Defaults.DEFAULT_ITERATIONS);
    int keyLengthBytes = intOrDefault(defaults, Pbkdf2ParameterNames.KEY_LENGTH,
        Pbkdf2Defaults.DEFAULT_KEY_LENGTH);
    int saltLengthBytes = Pbkdf2Defaults.DEFAULT_SALT_LENGTH;

    byte[] salt = new byte[saltLengthBytes];
    random.nextBytes(salt);
    byte[] derived = null;
    try {
      derived = deriveKey(password, salt, iterations, keyLengthBytes);
      Map<String, String> params = new LinkedHashMap<>();
      params.put(Pbkdf2ParameterNames.ITERATIONS, Integer.toString(iterations));
      params.put(Pbkdf2ParameterNames.KEY_LENGTH,
          Integer.toString(keyLengthBytes));
      params.put(Pbkdf2ParameterNames.SALT,
          Base64.getEncoder().encodeToString(salt));

      PasswordHashEnvelope envelope = new PasswordHashEnvelope(
          policy.preferredFormatVersion(),
          CredentialType.PASSWORD,
          algorithm(),
          providerId(),
          policy.policyVersion(),
          Optional.empty(),
          params,
          Base64.getEncoder().encodeToString(derived)
      );
      String encoded = codec.encode(envelope);

      return new PasswordHashResult(
          encoded,
          CredentialType.PASSWORD,
          envelope.formatVersion().wireValue(),
          algorithm(),
          providerId(),
          policy.policyVersion(),
          Optional.empty(),
          params
      );
    } finally {
      Arrays.fill(salt, (byte) 0);
      if (derived != null) {
        Arrays.fill(derived, (byte) 0);
      }
    }
  }

  @Override
  public ProviderVerificationResult verify(
      char[] password,
      PasswordHashEnvelope envelope,
      Optional<byte[]> pepperSecret) {
    Objects.requireNonNull(password, "password");
    Objects.requireNonNull(envelope, "envelope");
    Objects.requireNonNull(pepperSecret, "pepperSecret");

    Map<String, String> params = envelope.parameters();
    int iterations;
    int keyLengthBytes;
    byte[] salt;
    byte[] expectedDerived;
    try {
      iterations = Integer.parseInt(
          Objects.requireNonNull(params.get(Pbkdf2ParameterNames.ITERATIONS)));
      keyLengthBytes = Integer.parseInt(
          Objects.requireNonNull(params.get(Pbkdf2ParameterNames.KEY_LENGTH)));
      salt = Base64.getDecoder().decode(
          Objects.requireNonNull(params.get(Pbkdf2ParameterNames.SALT)));
      expectedDerived = Base64.getDecoder().decode(envelope.innerHash());
    } catch (NullPointerException | IllegalArgumentException e) {
      return new ProviderVerificationResult.ProviderError(
          InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
          "pbkdf2 envelope parameters are not parseable");
    }

    byte[] candidate = null;
    try {
      candidate = deriveKey(password, salt, iterations, keyLengthBytes);
      return MessageDigest.isEqual(candidate, expectedDerived)
          ? ProviderVerificationResult.Matched.INSTANCE
          : ProviderVerificationResult.NotMatched.INSTANCE;
    } catch (Pbkdf2ProviderException e) {
      return new ProviderVerificationResult.ProviderError(
          e.auditEventType(), e.getMessage());
    } finally {
      Arrays.fill(salt, (byte) 0);
      Arrays.fill(expectedDerived, (byte) 0);
      if (candidate != null) {
        Arrays.fill(candidate, (byte) 0);
      }
    }
  }

  private byte[] deriveKey(
      char[] password, byte[] salt, int iterations, int keyLengthBytes) {
    PBEKeySpec spec = new PBEKeySpec(
        password, salt, iterations, keyLengthBytes * 8);
    try {
      SecretKeyFactory factory;
      if (jcaProviderName.isPresent()) {
        factory = SecretKeyFactory.getInstance(
            algorithm(), jcaProviderName.get());
      } else {
        factory = SecretKeyFactory.getInstance(algorithm());
      }
      SecretKey key = factory.generateSecret(spec);
      return key.getEncoded();
    } catch (NoSuchAlgorithmException e) {
      throw new Pbkdf2ProviderException(
          InternalAuditEventType.VERIFICATION_FAILED_UNSUPPORTED_ALGORITHM,
          "pbkdf2 algorithm not available in the configured JCA provider");
    } catch (NoSuchProviderException e) {
      throw new Pbkdf2ProviderException(
          InternalAuditEventType.VERIFICATION_FAILED_UNKNOWN_PROVIDER,
          "configured JCA provider not registered");
    } catch (InvalidKeySpecException e) {
      throw new Pbkdf2ProviderException(
          InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
          "pbkdf2 key specification rejected by the JCA provider");
    } finally {
      spec.clearPassword();
    }
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
   * Provider-internal control-flow exception. Never propagates outside
   * the provider; always caught and converted to a
   * {@link ProviderVerificationResult.ProviderError}.
   */
  static final class Pbkdf2ProviderException extends RuntimeException {
    private final InternalAuditEventType auditEventType;

    Pbkdf2ProviderException(InternalAuditEventType auditEventType,
                            String message) {
      super(message);
      this.auditEventType = auditEventType;
    }

    InternalAuditEventType auditEventType() {
      return auditEventType;
    }
  }

}
