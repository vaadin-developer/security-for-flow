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
package eu.jsentinel.jcustos.credential.password.bouncycastle.scrypt;

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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScryptPasswordHashProviderTest {

  /** Fast test policy: N=2^10=1024 → ~16 KiB working set per call. */
  private static PasswordHashPolicy fastTestPolicy() {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(ScryptParameterNames.N, "1024");
    defaults.put(ScryptParameterNames.R, "8");
    defaults.put(ScryptParameterNames.P, "1");
    defaults.put(ScryptParameterNames.HASH_LENGTH, "32");
    Map<String, String> min = new LinkedHashMap<>();
    min.put(ScryptParameterNames.N, "512");
    min.put(ScryptParameterNames.R, "4");
    min.put(ScryptParameterNames.P, "1");
    min.put(ScryptParameterNames.HASH_LENGTH, "32");
    min.put(ScryptParameterNames.SALT_LENGTH, "16");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(ScryptParameterNames.N, "2048");
    max.put(ScryptParameterNames.R, "16");
    max.put(ScryptParameterNames.P, "4");
    max.put(ScryptParameterNames.HASH_LENGTH, "64");
    max.put(ScryptParameterNames.SALT_LENGTH, "64");
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(ScryptParameterNames.ALGORITHM)
        .preferredProviderId(ScryptParameterNames.PROVIDER_ID)
        .defaultParameters(ScryptParameterNames.ALGORITHM, defaults)
        .minimumParameters(ScryptParameterNames.ALGORITHM, min)
        .maximumParameters(ScryptParameterNames.ALGORITHM, max)
        .build();
  }

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

  private final ScryptPasswordHashProvider provider = new ScryptPasswordHashProvider();

  @Test
  @DisplayName("hash + verify roundtrip matches on the same password")
  void roundtripMatches() {
    PasswordHashResult r = provider.hash(
        "hunter2".toCharArray(), fastTestPolicy(), Optional.empty());
    assertEquals(CredentialType.PASSWORD, r.credentialType());
    assertEquals(ScryptParameterNames.ALGORITHM, r.algorithm());
    assertEquals(ScryptParameterNames.PROVIDER_ID, r.providerId());

    PasswordHashEnvelope env = PasswordHashCodec.DEFAULT
        .decode(r.encodedHash()).envelope();
    assertSame(ProviderVerificationResult.Matched.INSTANCE,
        provider.verify("hunter2".toCharArray(), env, Optional.empty()));
  }

  @Test
  @DisplayName("Wrong password yields NotMatched without throwing")
  void wrongPasswordReturnsNotMatched() {
    PasswordHashResult r = provider.hash(
        "hunter2".toCharArray(), fastTestPolicy(), Optional.empty());
    PasswordHashEnvelope env = PasswordHashCodec.DEFAULT
        .decode(r.encodedHash()).envelope();
    assertSame(ProviderVerificationResult.NotMatched.INSTANCE,
        provider.verify("hunter3".toCharArray(), env, Optional.empty()));
  }

  @Test
  @DisplayName("Two hashes of the same password use different salts")
  void freshSaltPerHash() {
    PasswordHashPolicy policy = fastTestPolicy();
    PasswordHashResult a = provider.hash("hunter2".toCharArray(), policy, Optional.empty());
    PasswordHashResult b = provider.hash("hunter2".toCharArray(), policy, Optional.empty());
    assertNotEquals(a.encodedHash(), b.encodedHash());
  }

  @Test
  @DisplayName("Hash output uses the $pwh$ envelope format with scrypt alg/prov")
  void outputUsesNewEnvelopeFormat() {
    PasswordHashResult r = provider.hash(
        "x".toCharArray(), fastTestPolicy(), Optional.empty());
    assertTrue(r.encodedHash().startsWith("$pwh$v=1$"));
    assertTrue(r.encodedHash().contains("$alg=scrypt$"));
    assertTrue(r.encodedHash().contains("$prov=scrypt-bc$"));
    assertTrue(r.encodedHash().contains("$p=n=1024,r=8,p=1,"));
  }

  @Test
  @DisplayName("Provider honours policy parameter values")
  void honoursPolicyParameters() {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(ScryptParameterNames.N, "2048");
    defaults.put(ScryptParameterNames.R, "8");
    defaults.put(ScryptParameterNames.P, "2");
    defaults.put(ScryptParameterNames.HASH_LENGTH, "48");
    Map<String, String> min = new LinkedHashMap<>(defaults);
    min.put(ScryptParameterNames.SALT_LENGTH, "16");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(ScryptParameterNames.N, "4096");
    max.put(ScryptParameterNames.R, "16");
    max.put(ScryptParameterNames.P, "4");
    max.put(ScryptParameterNames.HASH_LENGTH, "64");
    max.put(ScryptParameterNames.SALT_LENGTH, "64");
    PasswordHashPolicy policy = DefaultPasswordHashPolicy.builder()
        .preferredAlgorithm(ScryptParameterNames.ALGORITHM)
        .preferredProviderId(ScryptParameterNames.PROVIDER_ID)
        .defaultParameters(ScryptParameterNames.ALGORITHM, defaults)
        .minimumParameters(ScryptParameterNames.ALGORITHM, min)
        .maximumParameters(ScryptParameterNames.ALGORITHM, max)
        .build();

    PasswordHashResult r = provider.hash("x".toCharArray(), policy, Optional.empty());
    PasswordHashEnvelope env = PasswordHashCodec.DEFAULT
        .decode(r.encodedHash()).envelope();
    assertEquals("2048", env.parameters().get(ScryptParameterNames.N));
    assertEquals("8", env.parameters().get(ScryptParameterNames.R));
    assertEquals("2", env.parameters().get(ScryptParameterNames.P));
    assertEquals("48", env.parameters().get(ScryptParameterNames.HASH_LENGTH));
  }

  @Test
  @DisplayName("Deterministic salt produces a deterministic envelope")
  void deterministicEnvelope() {
    byte[] salt = new byte[ScryptDefaults.DEFAULT_SALT_LENGTH];
    Arrays.fill(salt, (byte) 0x44);
    ScryptPasswordHashProvider deterministic = new ScryptPasswordHashProvider(
        PasswordHashCodec.DEFAULT, new FixedSecureRandom(salt));
    PasswordHashResult a = deterministic.hash("k".toCharArray(),
        fastTestPolicy(), Optional.empty());
    PasswordHashResult b = deterministic.hash("k".toCharArray(),
        fastTestPolicy(), Optional.empty());
    assertEquals(a.encodedHash(), b.encodedHash());
  }

  @Test
  @DisplayName("verify returns ProviderError on malformed parameters")
  void malformedParameters() {
    Map<String, String> bad = new LinkedHashMap<>();
    bad.put(ScryptParameterNames.N, "nope");
    bad.put(ScryptParameterNames.R, "8");
    bad.put(ScryptParameterNames.P, "1");
    bad.put(ScryptParameterNames.HASH_LENGTH, "32");
    bad.put(ScryptParameterNames.SALT, "AAAAAAAAAAAAAAAAAAAAAA==");
    PasswordHashEnvelope env = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1, CredentialType.PASSWORD,
        ScryptParameterNames.ALGORITHM, ScryptParameterNames.PROVIDER_ID,
        1, Optional.empty(), bad, "ZGVyaXZlZA==");
    assertInstanceOf(ProviderVerificationResult.ProviderError.class,
        provider.verify("x".toCharArray(), env, Optional.empty()));
  }

  @Test
  @DisplayName("verify rejects an over-ceiling N parameter before allocating (R017)")
  void verifyRejectsOverCeilingNBeforeAllocation() {
    Map<String, String> tampered = new LinkedHashMap<>();
    // N = 2^30 is far above MAX_N (2^20). scrypt memory ~ 128 * r * N, so without
    // the guard this would attempt a multi-GB allocation. It must be rejected
    // BEFORE allocation — the test returning promptly is the proof.
    tampered.put(ScryptParameterNames.N, Integer.toString(1 << 30));
    tampered.put(ScryptParameterNames.R, "8");
    tampered.put(ScryptParameterNames.P, "1");
    tampered.put(ScryptParameterNames.HASH_LENGTH, "32");
    tampered.put(ScryptParameterNames.SALT, "AAAAAAAAAAAAAAAAAAAAAA==");
    PasswordHashEnvelope env = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1, CredentialType.PASSWORD,
        ScryptParameterNames.ALGORITHM, ScryptParameterNames.PROVIDER_ID,
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
  @DisplayName("ResourceEstimate scales with N and r (memory = 128 * r * N)")
  void resourceEstimateScales() {
    Map<String, String> small = new LinkedHashMap<>();
    small.put(ScryptParameterNames.N, "1024");
    small.put(ScryptParameterNames.R, "8");
    small.put(ScryptParameterNames.P, "1");

    Map<String, String> big = new LinkedHashMap<>();
    big.put(ScryptParameterNames.N, "4096");
    big.put(ScryptParameterNames.R, "16");
    big.put(ScryptParameterNames.P, "1");

    ResourceEstimate eSmall = provider.resourceEstimate(small);
    ResourceEstimate eBig = provider.resourceEstimate(big);
    assertEquals(128L * 8L * 1024L, eSmall.estimatedMemoryBytes());
    assertEquals(128L * 16L * 4096L, eBig.estimatedMemoryBytes());
    assertTrue(eBig.estimatedCpuTimeMicros() > eSmall.estimatedCpuTimeMicros());
  }

  @Test
  @DisplayName("Provider identifies itself with the canonical id and algorithm")
  void identifiers() {
    assertEquals(ScryptParameterNames.PROVIDER_ID, provider.providerId());
    assertEquals(ScryptParameterNames.ALGORITHM, provider.algorithm());
    assertTrue(provider.supports(provider.providerId(), provider.algorithm()));
  }
}
