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
package com.svenruppert.vaadin.security.credential.password.bouncycastle.scrypt;

import com.svenruppert.vaadin.security.credential.CredentialType;
import com.svenruppert.vaadin.security.credential.InternalAuditEventType;
import com.svenruppert.vaadin.security.credential.password.PasswordHashResult;
import com.svenruppert.vaadin.security.credential.password.ProviderVerificationResult;
import com.svenruppert.vaadin.security.credential.password.envelope.PasswordHashCodec;
import com.svenruppert.vaadin.security.credential.password.envelope.PasswordHashEnvelope;
import com.svenruppert.vaadin.security.credential.password.policy.PasswordHashPolicy;
import com.svenruppert.vaadin.security.credential.password.provider.PasswordHashProvider;
import com.svenruppert.vaadin.security.credential.password.provider.ResourceEstimate;
import org.bouncycastle.crypto.generators.SCrypt;

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
 * scrypt password hash provider backed by BouncyCastle's low-level
 * {@link SCrypt} generator. No JCA provider registration; this
 * provider uses the lightweight Bouncy Castle Crypto API directly.
 *
 * <p>Implementation notes:</p>
 * <ul>
 *   <li>Salt drawn fresh per {@code hash(...)} call from a
 *       caller-supplied {@link SecureRandom} (CWE-759 / CWE-760).</li>
 *   <li>Constant-time compare via
 *       {@link MessageDigest#isEqual(byte[], byte[])}.</li>
 *   <li>Temporary {@code byte[]} arrays carrying password, salt and
 *       derived key material are zeroed in {@code finally} blocks.</li>
 *   <li>{@link ResourceEstimate} reports {@code 128 * r * N} bytes as
 *       peak memory and a coarse {@code N * r} µs CPU figure so the
 *       core budget layer has a real signal to work against.</li>
 * </ul>
 */
public final class ScryptPasswordHashProvider implements PasswordHashProvider {

  private final PasswordHashCodec codec;
  private final SecureRandom random;

  public ScryptPasswordHashProvider() {
    this(PasswordHashCodec.DEFAULT, new SecureRandom());
  }

  public ScryptPasswordHashProvider(
      PasswordHashCodec codec, SecureRandom random) {
    this.codec = Objects.requireNonNull(codec, "codec");
    this.random = Objects.requireNonNull(random, "random");
  }

  @Override
  public String providerId() {
    return ScryptParameterNames.PROVIDER_ID;
  }

  @Override
  public String algorithm() {
    return ScryptParameterNames.ALGORITHM;
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
    int n = intOrDefault(defaults, ScryptParameterNames.N, ScryptDefaults.DEFAULT_N);
    int r = intOrDefault(defaults, ScryptParameterNames.R, ScryptDefaults.DEFAULT_R);
    int p = intOrDefault(defaults, ScryptParameterNames.P, ScryptDefaults.DEFAULT_P);
    int hashLength = intOrDefault(defaults,
        ScryptParameterNames.HASH_LENGTH, ScryptDefaults.DEFAULT_HASH_LENGTH);

    byte[] salt = new byte[ScryptDefaults.DEFAULT_SALT_LENGTH];
    random.nextBytes(salt);
    byte[] pwBytes = toUtf8(password);
    byte[] derived = null;
    try {
      derived = SCrypt.generate(pwBytes, salt, n, r, p, hashLength);
      Map<String, String> params = new LinkedHashMap<>();
      params.put(ScryptParameterNames.N, Integer.toString(n));
      params.put(ScryptParameterNames.R, Integer.toString(r));
      params.put(ScryptParameterNames.P, Integer.toString(p));
      params.put(ScryptParameterNames.HASH_LENGTH, Integer.toString(hashLength));
      params.put(ScryptParameterNames.SALT,
          Base64.getEncoder().encodeToString(salt));

      PasswordHashEnvelope envelope = new PasswordHashEnvelope(
          policy.preferredFormatVersion(),
          CredentialType.PASSWORD,
          algorithm(),
          providerId(),
          policy.policyVersion(),
          Optional.empty(),
          params,
          Base64.getEncoder().encodeToString(derived));
      String encoded = codec.encode(envelope);

      return new PasswordHashResult(
          encoded,
          CredentialType.PASSWORD,
          envelope.formatVersion().wireValue(),
          algorithm(),
          providerId(),
          policy.policyVersion(),
          Optional.empty(),
          params);
    } finally {
      Arrays.fill(salt, (byte) 0);
      Arrays.fill(pwBytes, (byte) 0);
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
    int n;
    int r;
    int p;
    int hashLength;
    byte[] salt;
    byte[] expectedDerived;
    try {
      n = Integer.parseInt(Objects.requireNonNull(
          params.get(ScryptParameterNames.N)));
      r = Integer.parseInt(Objects.requireNonNull(
          params.get(ScryptParameterNames.R)));
      p = Integer.parseInt(Objects.requireNonNull(
          params.get(ScryptParameterNames.P)));
      hashLength = Integer.parseInt(Objects.requireNonNull(
          params.get(ScryptParameterNames.HASH_LENGTH)));
      salt = Base64.getDecoder().decode(Objects.requireNonNull(
          params.get(ScryptParameterNames.SALT)));
      expectedDerived = Base64.getDecoder().decode(envelope.innerHash());
    } catch (NullPointerException | IllegalArgumentException e) {
      return new ProviderVerificationResult.ProviderError(
          InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
          "scrypt envelope parameters are not parseable");
    }

    byte[] pwBytes = toUtf8(password);
    byte[] candidate = null;
    try {
      candidate = SCrypt.generate(pwBytes, salt, n, r, p, hashLength);
      return MessageDigest.isEqual(candidate, expectedDerived)
          ? ProviderVerificationResult.Matched.INSTANCE
          : ProviderVerificationResult.NotMatched.INSTANCE;
    } catch (RuntimeException e) {
      return new ProviderVerificationResult.ProviderError(
          InternalAuditEventType.VERIFICATION_FAILED_PROVIDER_ERROR,
          "scrypt generator rejected the parameters");
    } finally {
      Arrays.fill(pwBytes, (byte) 0);
      Arrays.fill(salt, (byte) 0);
      Arrays.fill(expectedDerived, (byte) 0);
      if (candidate != null) {
        Arrays.fill(candidate, (byte) 0);
      }
    }
  }

  @Override
  public ResourceEstimate resourceEstimate(Map<String, String> parameters) {
    Objects.requireNonNull(parameters, "parameters");
    int n = intOrDefault(parameters, ScryptParameterNames.N, ScryptDefaults.DEFAULT_N);
    int r = intOrDefault(parameters, ScryptParameterNames.R, ScryptDefaults.DEFAULT_R);
    int p = intOrDefault(parameters, ScryptParameterNames.P, ScryptDefaults.DEFAULT_P);
    long memoryBytes = 128L * (long) r * (long) n;
    long cpuMicros = Math.max(1L, ((long) n * (long) r * (long) p));
    return new ResourceEstimate(cpuMicros, memoryBytes);
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
}
