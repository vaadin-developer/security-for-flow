/*-
 * #%L
 * Security Crypto — BouncyCastle
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
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
package eu.jsentinel.jcustos.credential.password.bouncycastle.argon2;

import eu.jsentinel.jcustos.credential.CredentialType;
import eu.jsentinel.jcustos.credential.InternalAuditEventType;
import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.ProviderVerificationResult;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashCodec;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashEnvelope;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashFormatVersion;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.provider.ResourceEstimate;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Argon2idPasswordHashProviderTest {

  /** Fast test policy: 1 iteration, 8&nbsp;MiB memory, 1 lane. */
  private static PasswordHashPolicy fastTestPolicy() {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(Argon2idParameterNames.ITERATIONS, "1");
    defaults.put(Argon2idParameterNames.MEMORY_KIB, "8192");
    defaults.put(Argon2idParameterNames.PARALLELISM, "1");
    defaults.put(Argon2idParameterNames.HASH_LENGTH, "32");
    Map<String, String> min = new LinkedHashMap<>();
    min.put(Argon2idParameterNames.ITERATIONS, "1");
    min.put(Argon2idParameterNames.MEMORY_KIB, "8192");
    min.put(Argon2idParameterNames.PARALLELISM, "1");
    min.put(Argon2idParameterNames.HASH_LENGTH, "32");
    min.put(Argon2idParameterNames.SALT_LENGTH, "16");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(Argon2idParameterNames.ITERATIONS, "5");
    max.put(Argon2idParameterNames.MEMORY_KIB, "65536");
    max.put(Argon2idParameterNames.PARALLELISM, "4");
    max.put(Argon2idParameterNames.HASH_LENGTH, "64");
    max.put(Argon2idParameterNames.SALT_LENGTH, "64");
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(Argon2idParameterNames.ALGORITHM)
        .preferredProviderId(Argon2idParameterNames.PROVIDER_ID)
        .defaultParameters(Argon2idParameterNames.ALGORITHM, defaults)
        .minimumParameters(Argon2idParameterNames.ALGORITHM, min)
        .maximumParameters(Argon2idParameterNames.ALGORITHM, max)
        .build();
  }

  /** SecureRandom that always emits the same bytes. */
  private static final class FixedSecureRandom extends SecureRandom {
    private final byte[] fixed;

    FixedSecureRandom(byte[] fixed) {
      this.fixed = fixed.clone();
    }

    @Override
    public void nextBytes(byte[] bytes) {
      if (bytes.length != fixed.length) {
        throw new IllegalStateException(
            "expected " + fixed.length + " salt bytes, got " + bytes.length);
      }
      System.arraycopy(fixed, 0, bytes, 0, fixed.length);
    }
  }

  private final Argon2idPasswordHashProvider provider =
      new Argon2idPasswordHashProvider();

  @Test
  @DisplayName("hash + verify roundtrip matches on the same password")
  void roundtripMatchesSamePassword() {
    PasswordHashPolicy policy = fastTestPolicy();
    PasswordHashResult result = provider.hash(
        "hunter2".toCharArray(), policy, Optional.empty());
    assertEquals(CredentialType.PASSWORD, result.credentialType());
    assertEquals(Argon2idParameterNames.ALGORITHM, result.algorithm());
    assertEquals(Argon2idParameterNames.PROVIDER_ID, result.providerId());

    PasswordHashEnvelope env = PasswordHashCodec.DEFAULT
        .decode(result.encodedHash()).envelope();
    assertSame(ProviderVerificationResult.Matched.INSTANCE,
        provider.verify("hunter2".toCharArray(), env, Optional.empty()));
  }

  @Test
  @DisplayName("Wrong password produces NotMatched, not an exception")
  void wrongPasswordReturnsNotMatched() {
    PasswordHashResult result = provider.hash(
        "hunter2".toCharArray(), fastTestPolicy(), Optional.empty());
    PasswordHashEnvelope env = PasswordHashCodec.DEFAULT
        .decode(result.encodedHash()).envelope();
    assertSame(ProviderVerificationResult.NotMatched.INSTANCE,
        provider.verify("hunter3".toCharArray(), env, Optional.empty()));
  }

  @Test
  @DisplayName("Two hashes of the same password use different salts")
  void freshSaltPerHash() {
    PasswordHashPolicy policy = fastTestPolicy();
    PasswordHashResult a = provider.hash(
        "hunter2".toCharArray(), policy, Optional.empty());
    PasswordHashResult b = provider.hash(
        "hunter2".toCharArray(), policy, Optional.empty());
    assertNotEquals(a.encodedHash(), b.encodedHash());
    PasswordHashEnvelope envA = PasswordHashCodec.DEFAULT.decode(a.encodedHash()).envelope();
    PasswordHashEnvelope envB = PasswordHashCodec.DEFAULT.decode(b.encodedHash()).envelope();
    assertNotEquals(
        envA.parameters().get(Argon2idParameterNames.SALT),
        envB.parameters().get(Argon2idParameterNames.SALT));
  }

  @Test
  @DisplayName("Hash output uses the new $pwh$ envelope format")
  void outputUsesNewEnvelopeFormat() {
    PasswordHashResult r = provider.hash(
        "x".toCharArray(), fastTestPolicy(), Optional.empty());
    assertTrue(r.encodedHash().startsWith("$pwh$v=1$"));
    assertTrue(r.encodedHash().contains("$alg=Argon2id$"));
    assertTrue(r.encodedHash().contains("$prov=argon2id-bc$"));
  }

  @Test
  @DisplayName("Provider honours policy parameter values")
  void honoursPolicyParameters() {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(Argon2idParameterNames.ITERATIONS, "2");
    defaults.put(Argon2idParameterNames.MEMORY_KIB, "8192");
    defaults.put(Argon2idParameterNames.PARALLELISM, "1");
    defaults.put(Argon2idParameterNames.HASH_LENGTH, "48");
    Map<String, String> min = new LinkedHashMap<>(defaults);
    min.put(Argon2idParameterNames.SALT_LENGTH, "16");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(Argon2idParameterNames.ITERATIONS, "5");
    max.put(Argon2idParameterNames.MEMORY_KIB, "16384");
    max.put(Argon2idParameterNames.PARALLELISM, "2");
    max.put(Argon2idParameterNames.HASH_LENGTH, "64");
    max.put(Argon2idParameterNames.SALT_LENGTH, "64");
    PasswordHashPolicy policy = DefaultPasswordHashPolicy.builder()
        .preferredAlgorithm(Argon2idParameterNames.ALGORITHM)
        .preferredProviderId(Argon2idParameterNames.PROVIDER_ID)
        .defaultParameters(Argon2idParameterNames.ALGORITHM, defaults)
        .minimumParameters(Argon2idParameterNames.ALGORITHM, min)
        .maximumParameters(Argon2idParameterNames.ALGORITHM, max)
        .build();

    PasswordHashResult r = provider.hash(
        "x".toCharArray(), policy, Optional.empty());
    PasswordHashEnvelope env = PasswordHashCodec.DEFAULT
        .decode(r.encodedHash()).envelope();
    assertEquals("2", env.parameters().get(Argon2idParameterNames.ITERATIONS));
    assertEquals("8192", env.parameters().get(Argon2idParameterNames.MEMORY_KIB));
    assertEquals("1", env.parameters().get(Argon2idParameterNames.PARALLELISM));
    assertEquals("48", env.parameters().get(Argon2idParameterNames.HASH_LENGTH));
    byte[] decodedSalt = Base64.getDecoder()
        .decode(env.parameters().get(Argon2idParameterNames.SALT));
    assertEquals(Argon2idDefaults.DEFAULT_SALT_LENGTH, decodedSalt.length);
    byte[] inner = Base64.getDecoder().decode(env.innerHash());
    assertEquals(48, inner.length);
  }

  @Test
  @DisplayName("Deterministic salt produces a deterministic envelope")
  void deterministicSaltProducesDeterministicEnvelope() {
    byte[] salt = new byte[16];
    Arrays.fill(salt, (byte) 0x22);
    Argon2idPasswordHashProvider deterministic = new Argon2idPasswordHashProvider(
        PasswordHashCodec.DEFAULT, new FixedSecureRandom(salt));
    PasswordHashPolicy policy = fastTestPolicy();
    PasswordHashResult a = deterministic.hash("knownpw".toCharArray(), policy, Optional.empty());
    PasswordHashResult b = deterministic.hash("knownpw".toCharArray(), policy, Optional.empty());
    assertEquals(a.encodedHash(), b.encodedHash(),
        "deterministic salt + parameters must produce identical envelopes");
  }

  @Test
  @DisplayName("verify returns ProviderError when stored parameters are malformed")
  void verifyReturnsProviderErrorOnMalformedParameters() {
    Map<String, String> bad = new LinkedHashMap<>();
    bad.put(Argon2idParameterNames.ITERATIONS, "not-a-number");
    bad.put(Argon2idParameterNames.MEMORY_KIB, "8192");
    bad.put(Argon2idParameterNames.PARALLELISM, "1");
    bad.put(Argon2idParameterNames.HASH_LENGTH, "32");
    bad.put(Argon2idParameterNames.SALT, "AAAAAAAAAAAAAAAAAAAAAA==");
    PasswordHashEnvelope env = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1,
        CredentialType.PASSWORD,
        Argon2idParameterNames.ALGORITHM,
        Argon2idParameterNames.PROVIDER_ID,
        1, Optional.empty(), bad, "ZGVyaXZlZA==");
    ProviderVerificationResult result = provider.verify(
        "x".toCharArray(), env, Optional.empty());
    assertInstanceOf(ProviderVerificationResult.ProviderError.class, result);
  }

  @Test
  @DisplayName("verify rejects an over-ceiling memory parameter before allocating (R017)")
  void verifyRejectsOverCeilingMemoryBeforeAllocation() {
    Map<String, String> tampered = new LinkedHashMap<>();
    tampered.put(Argon2idParameterNames.ITERATIONS, "3");
    // 2_000_000 KiB (~2 GiB) is well above MAX_MEMORY_KIB (1 GiB). It must be
    // rejected BEFORE any allocation — the test returning promptly is the proof
    // (without the guard BouncyCastle would attempt a multi-GB allocation).
    tampered.put(Argon2idParameterNames.MEMORY_KIB, "2000000");
    tampered.put(Argon2idParameterNames.PARALLELISM, "1");
    tampered.put(Argon2idParameterNames.HASH_LENGTH, "32");
    tampered.put(Argon2idParameterNames.SALT, "AAAAAAAAAAAAAAAAAAAAAA==");
    PasswordHashEnvelope env = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1,
        CredentialType.PASSWORD,
        Argon2idParameterNames.ALGORITHM,
        Argon2idParameterNames.PROVIDER_ID,
        1, Optional.empty(), tampered, "ZGVyaXZlZA==");
    ProviderVerificationResult result = provider.verify(
        "x".toCharArray(), env, Optional.empty());
    ProviderVerificationResult.ProviderError error = assertInstanceOf(
        ProviderVerificationResult.ProviderError.class, result);
    assertEquals(InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
        error.internalAuditEventType());
    assertTrue(error.message().contains("exceed safe limits"));
  }

  @Test
  @DisplayName("ResourceEstimate scales with iterations and memory")
  void resourceEstimateScalesWithParameters() {
    Map<String, String> small = new LinkedHashMap<>();
    small.put(Argon2idParameterNames.ITERATIONS, "1");
    small.put(Argon2idParameterNames.MEMORY_KIB, "8192");
    small.put(Argon2idParameterNames.PARALLELISM, "1");

    Map<String, String> big = new LinkedHashMap<>();
    big.put(Argon2idParameterNames.ITERATIONS, "4");
    big.put(Argon2idParameterNames.MEMORY_KIB, "65536");
    big.put(Argon2idParameterNames.PARALLELISM, "1");

    ResourceEstimate eSmall = provider.resourceEstimate(small);
    ResourceEstimate eBig = provider.resourceEstimate(big);
    assertTrue(eBig.estimatedCpuTimeMicros()
        > eSmall.estimatedCpuTimeMicros());
    assertTrue(eBig.estimatedMemoryBytes()
        > eSmall.estimatedMemoryBytes());
    assertEquals(8192L * 1024L, eSmall.estimatedMemoryBytes());
  }

  @Test
  @DisplayName("Provider identifies itself with the canonical id and algorithm")
  void identifiers() {
    assertEquals(Argon2idParameterNames.PROVIDER_ID, provider.providerId());
    assertEquals(Argon2idParameterNames.ALGORITHM, provider.algorithm());
    assertTrue(provider.supports(provider.providerId(), provider.algorithm()));
  }
}
