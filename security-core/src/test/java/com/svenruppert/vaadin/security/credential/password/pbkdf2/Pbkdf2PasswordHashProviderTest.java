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
import com.svenruppert.vaadin.security.credential.password.PasswordHashResult;
import com.svenruppert.vaadin.security.credential.password.ProviderVerificationResult;
import com.svenruppert.vaadin.security.credential.password.envelope.PasswordHashCodec;
import com.svenruppert.vaadin.security.credential.password.envelope.PasswordHashEnvelope;
import com.svenruppert.vaadin.security.credential.password.envelope.PasswordHashFormatVersion;
import com.svenruppert.vaadin.security.credential.password.policy.DefaultPasswordHashPolicy;
import com.svenruppert.vaadin.security.credential.password.policy.PasswordHashPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Pbkdf2PasswordHashProviderTest {

  /**
   * Fast test policy: same algorithm and provider id as production but
   * with reduced iteration bounds so the test suite stays sub-second.
   */
  private static PasswordHashPolicy fastTestPolicy() {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    defaults.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    Map<String, String> min = new LinkedHashMap<>();
    min.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    min.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    min.put(Pbkdf2ParameterNames.SALT_LENGTH, "16");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(Pbkdf2ParameterNames.ITERATIONS, "2000");
    max.put(Pbkdf2ParameterNames.KEY_LENGTH, "64");
    max.put(Pbkdf2ParameterNames.SALT_LENGTH, "64");
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(7)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, defaults)
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, min)
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, max)
        .build();
  }

  /** SecureRandom that always returns the same bytes. */
  private static final class FixedSecureRandom extends SecureRandom {
    private final byte[] fixed;

    FixedSecureRandom(byte[] fixed) {
      this.fixed = fixed.clone();
    }

    @Override
    public void nextBytes(byte[] bytes) {
      if (bytes.length != fixed.length) {
        throw new IllegalStateException(
            "Test expected " + fixed.length + " salt bytes, got " + bytes.length);
      }
      System.arraycopy(fixed, 0, bytes, 0, fixed.length);
    }
  }

  private final Pbkdf2PasswordHashProvider provider =
      new Pbkdf2PasswordHashProvider();

  @Test
  @DisplayName("hash + verify roundtrip matches on the same password")
  void roundtripMatchesSamePassword() {
    PasswordHashPolicy policy = fastTestPolicy();
    PasswordHashResult result = provider.hash(
        "hunter2".toCharArray(), policy, Optional.empty());
    assertEquals(CredentialType.PASSWORD, result.credentialType());
    assertEquals(Pbkdf2ParameterNames.ALGORITHM, result.algorithm());
    assertEquals(Pbkdf2ParameterNames.PROVIDER_ID, result.providerId());
    assertEquals(7, result.policyVersion());

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
    assertNotEquals(a.encodedHash(), b.encodedHash(),
        "salt must be fresh per call (CWE-759/760)");

    PasswordHashEnvelope envA = PasswordHashCodec.DEFAULT
        .decode(a.encodedHash()).envelope();
    PasswordHashEnvelope envB = PasswordHashCodec.DEFAULT
        .decode(b.encodedHash()).envelope();
    assertNotEquals(
        envA.parameters().get(Pbkdf2ParameterNames.SALT),
        envB.parameters().get(Pbkdf2ParameterNames.SALT));
  }

  @Test
  @DisplayName("Hash output uses the new $pwh$ envelope format")
  void outputUsesNewEnvelopeFormat() {
    PasswordHashResult r = provider.hash(
        "x".toCharArray(), fastTestPolicy(), Optional.empty());
    assertTrue(r.encodedHash().startsWith("$pwh$v=1$"),
        "must emit the Phase-1a envelope, not the experimental format");
    assertFalse(r.encodedHash().startsWith("pbkdf2$"),
        "must not emit the experimental pbkdf2$ format");
  }

  @Test
  @DisplayName("Provider honours policy parameter values")
  void honoursPolicyParameters() {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(Pbkdf2ParameterNames.ITERATIONS, "1500");
    defaults.put(Pbkdf2ParameterNames.KEY_LENGTH, "48");
    Map<String, String> min = new LinkedHashMap<>(defaults);
    min.put(Pbkdf2ParameterNames.SALT_LENGTH, "16");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(Pbkdf2ParameterNames.ITERATIONS, "2000");
    max.put(Pbkdf2ParameterNames.KEY_LENGTH, "64");
    max.put(Pbkdf2ParameterNames.SALT_LENGTH, "64");
    PasswordHashPolicy policy = DefaultPasswordHashPolicy.builder()
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, defaults)
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, min)
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, max)
        .build();

    PasswordHashResult r = provider.hash(
        "x".toCharArray(), policy, Optional.empty());
    PasswordHashEnvelope env = PasswordHashCodec.DEFAULT
        .decode(r.encodedHash()).envelope();
    assertEquals("1500", env.parameters().get(Pbkdf2ParameterNames.ITERATIONS));
    assertEquals("48", env.parameters().get(Pbkdf2ParameterNames.KEY_LENGTH));
    byte[] decodedSalt = Base64.getDecoder()
        .decode(env.parameters().get(Pbkdf2ParameterNames.SALT));
    assertEquals(Pbkdf2Defaults.DEFAULT_SALT_LENGTH, decodedSalt.length);
  }

  @Test
  @DisplayName("Deterministic salt + iteration produce a deterministic envelope")
  void deterministicSaltProducesDeterministicEnvelope() {
    byte[] salt = new byte[16];
    Arrays.fill(salt, (byte) 0x11);
    Pbkdf2PasswordHashProvider deterministic = new Pbkdf2PasswordHashProvider(
        PasswordHashCodec.DEFAULT, new FixedSecureRandom(salt), Optional.empty());

    PasswordHashPolicy policy = fastTestPolicy();
    PasswordHashResult a = deterministic.hash(
        "knownpw".toCharArray(), policy, Optional.empty());
    PasswordHashResult b = deterministic.hash(
        "knownpw".toCharArray(), policy, Optional.empty());
    assertEquals(a.encodedHash(), b.encodedHash(),
        "deterministic salt + parameters must produce identical envelopes");
  }

  @Test
  @DisplayName("verify returns ProviderError when stored parameters are malformed")
  void verifyReturnsProviderErrorOnMalformedParameters() {
    Map<String, String> bad = new LinkedHashMap<>();
    bad.put(Pbkdf2ParameterNames.ITERATIONS, "not-a-number");
    bad.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    bad.put(Pbkdf2ParameterNames.SALT, "ZGVhZGJlZWY=");
    PasswordHashEnvelope env = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1,
        CredentialType.PASSWORD,
        Pbkdf2ParameterNames.ALGORITHM,
        Pbkdf2ParameterNames.PROVIDER_ID,
        1,
        Optional.empty(),
        bad,
        "ZGVyaXZlZA=="
    );

    ProviderVerificationResult result = provider.verify(
        "x".toCharArray(), env, Optional.empty());
    ProviderVerificationResult.ProviderError err = assertInstanceOf(
        ProviderVerificationResult.ProviderError.class, result);
    assertFalse(err.message().contains("x"),
        "provider error message must not leak the candidate password");
  }

  @Test
  @DisplayName("Pinning a non-existent JCA provider results in ProviderError on verify")
  void unknownJcaProviderProducesProviderError() {
    Pbkdf2PasswordHashProvider pinned = new Pbkdf2PasswordHashProvider(
        "Nonexistent_Provider_For_Tests");

    PasswordHashResult ok = new Pbkdf2PasswordHashProvider()
        .hash("x".toCharArray(), fastTestPolicy(), Optional.empty());
    PasswordHashEnvelope env = PasswordHashCodec.DEFAULT
        .decode(ok.encodedHash()).envelope();

    ProviderVerificationResult result = pinned.verify(
        "x".toCharArray(), env, Optional.empty());
    assertInstanceOf(ProviderVerificationResult.ProviderError.class, result);
  }

  @Test
  @DisplayName("Provider identifies itself with the canonical id and algorithm")
  void identifiers() {
    assertEquals(Pbkdf2ParameterNames.PROVIDER_ID, provider.providerId());
    assertEquals(Pbkdf2ParameterNames.ALGORITHM, provider.algorithm());
    assertTrue(provider.supports(provider.providerId(), provider.algorithm()));
  }

  @Test
  @DisplayName("Smoke test against the production OWASP-2023 defaults")
  void productionDefaultsSmokeTest() {
    PasswordHashPolicy policy = Pbkdf2Defaults.referencePolicy();
    PasswordHashResult r = provider.hash(
        "production-password".toCharArray(), policy, Optional.empty());
    PasswordHashEnvelope env = PasswordHashCodec.DEFAULT
        .decode(r.encodedHash()).envelope();
    assertSame(ProviderVerificationResult.Matched.INSTANCE,
        provider.verify("production-password".toCharArray(), env, Optional.empty()));
    assertEquals(Integer.toString(Pbkdf2Defaults.DEFAULT_ITERATIONS),
        env.parameters().get(Pbkdf2ParameterNames.ITERATIONS));
  }
}
