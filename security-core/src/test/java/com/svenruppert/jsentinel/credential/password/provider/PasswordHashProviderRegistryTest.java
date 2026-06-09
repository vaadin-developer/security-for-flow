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
package com.svenruppert.jsentinel.credential.password.provider;

import com.svenruppert.jsentinel.credential.CredentialType;
import com.svenruppert.jsentinel.credential.password.PasswordHashResult;
import com.svenruppert.jsentinel.credential.password.ProviderVerificationResult;
import com.svenruppert.jsentinel.credential.password.envelope.PasswordHashEnvelope;
import com.svenruppert.jsentinel.credential.password.envelope.PasswordHashFormatVersion;
import com.svenruppert.jsentinel.credential.password.pbkdf2.Pbkdf2Defaults;
import com.svenruppert.jsentinel.credential.password.policy.PasswordHashPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordHashProviderRegistryTest {

  /**
   * Second test-scope provider that always returns ProviderError; used
   * to exercise duplicate-id rejection and multi-provider resolution.
   */
  private static final class SecondFakeProvider implements PasswordHashProvider {

    static final String PROVIDER_ID = "fake-test-2";

    @Override
    public String providerId() {
      return PROVIDER_ID;
    }

    @Override
    public String algorithm() {
      return "FakeIdentity";
    }

    @Override
    public PasswordHashResult hash(
        char[] password,
        PasswordHashPolicy policy,
        Optional<com.svenruppert.jsentinel.credential.password.pepper.PepperReference> pepper) {
      return new PasswordHashResult(
          "x",
          CredentialType.PASSWORD,
          PasswordHashFormatVersion.CURRENT.wireValue(),
          algorithm(),
          providerId(),
          policy.policyVersion(),
          Optional.empty(),
          Map.of("len", "0"));
    }

    @Override
    public ProviderVerificationResult verify(
        char[] password,
        PasswordHashEnvelope envelope,
        Optional<com.svenruppert.jsentinel.credential.password.pepper.PepperReference> pepper) {
      return FakePasswordHashProvider.providerError("always fails");
    }
  }

  @Test
  @DisplayName("Two providers can be registered side by side")
  void multipleProvidersCanCoexist() {
    PasswordHashProviderRegistry registry = new PasswordHashProviderRegistry(
        List.of(new FakePasswordHashProvider(), new SecondFakeProvider()));
    assertEquals(2, registry.providers().size());
    assertTrue(registry.knownProviderIds()
        .contains(FakePasswordHashProvider.PROVIDER_ID));
    assertTrue(registry.knownProviderIds()
        .contains(SecondFakeProvider.PROVIDER_ID));
  }

  @Test
  @DisplayName("Duplicate provider ids are rejected at construction time")
  void duplicateProviderIdsAreRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> new PasswordHashProviderRegistry(List.of(
            new FakePasswordHashProvider(),
            new FakePasswordHashProvider())));
  }

  @Test
  @DisplayName("Resolution uses provider id + algorithm")
  void resolveByProviderIdAndAlgorithm() {
    PasswordHashProviderRegistry registry = new PasswordHashProviderRegistry(
        List.of(new FakePasswordHashProvider()));
    assertTrue(registry.resolve(FakePasswordHashProvider.PROVIDER_ID,
        FakePasswordHashProvider.ALGORITHM).isPresent());
  }

  @Test
  @DisplayName("Resolution returns empty when the provider id is unknown")
  void unknownProviderIdReturnsEmpty() {
    PasswordHashProviderRegistry registry = new PasswordHashProviderRegistry(
        List.of(new FakePasswordHashProvider()));
    assertTrue(registry.resolve("missing", "FakeIdentity").isEmpty());
  }

  @Test
  @DisplayName("Resolution returns empty when the algorithm does not match the provider")
  void wrongAlgorithmReturnsEmpty() {
    PasswordHashProviderRegistry registry = new PasswordHashProviderRegistry(
        List.of(new FakePasswordHashProvider()));
    assertTrue(registry.resolve(FakePasswordHashProvider.PROVIDER_ID,
        "DifferentAlgorithm").isEmpty());
  }

  @Test
  @DisplayName("Stored metadata pins the provider; policy choice never overrides it")
  void storedMetadataPinsProvider() {
    PasswordHashProviderRegistry registry = new PasswordHashProviderRegistry(
        List.of(new FakePasswordHashProvider(), new SecondFakeProvider()));

    PasswordHashEnvelope storedEnvelope = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1,
        CredentialType.PASSWORD,
        FakePasswordHashProvider.ALGORITHM,
        FakePasswordHashProvider.PROVIDER_ID,
        1,
        Optional.empty(),
        Map.of("len", "5"),
        "aGVsbG8=");

    PasswordHashProvider resolved = registry.resolve(
        storedEnvelope.providerId(),
        storedEnvelope.algorithm()).orElseThrow();
    assertInstanceOf(FakePasswordHashProvider.class, resolved);
  }

  @Test
  @DisplayName("Registry construction does not change the global JCA provider order")
  void jcaProviderOrderUntouched() {
    Provider[] beforeArr = Security.getProviders();
    String[] before = Arrays.stream(beforeArr).map(Provider::getName).toArray(String[]::new);

    new PasswordHashProviderRegistry(List.of(new FakePasswordHashProvider()));

    Provider[] afterArr = Security.getProviders();
    String[] after = Arrays.stream(afterArr).map(Provider::getName).toArray(String[]::new);
    assertEquals(before.length, after.length);
    for (int i = 0; i < before.length; i++) {
      assertEquals(before[i], after[i],
          "JCA provider order must not change at index " + i);
    }
  }

  @Test
  @DisplayName("ServiceLoader discovery picks up the test-scope provider")
  void serviceLoaderDiscoversTestProvider() {
    PasswordHashProviderRegistry registry =
        PasswordHashProviderRegistry.fromServiceLoader();
    assertTrue(registry.knownProviderIds()
        .contains(FakePasswordHashProvider.PROVIDER_ID),
        "Expected ServiceLoader to discover FakePasswordHashProvider");
  }

  @Test
  @DisplayName("Provider returns Matched/NotMatched without throwing on miss")
  void providerSemantics() {
    FakePasswordHashProvider provider = new FakePasswordHashProvider();
    PasswordHashPolicy policy = Pbkdf2Defaults.referencePolicy();

    PasswordHashResult result = provider.hash(
        "hunter2".toCharArray(), policy, Optional.empty());

    PasswordHashEnvelope envelope = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1,
        CredentialType.PASSWORD,
        FakePasswordHashProvider.ALGORITHM,
        FakePasswordHashProvider.PROVIDER_ID,
        result.policyVersion(),
        Optional.empty(),
        new LinkedHashMap<>(result.parameters()),
        "hunter2");

    assertSame(ProviderVerificationResult.Matched.INSTANCE,
        provider.verify("hunter2".toCharArray(), envelope, Optional.empty()));
    assertSame(ProviderVerificationResult.NotMatched.INSTANCE,
        provider.verify("hunter3".toCharArray(), envelope, Optional.empty()));
  }

  @Test
  @DisplayName("ResourceEstimate.UNKNOWN is the default; negative values are rejected")
  void resourceEstimateInvariants() {
    assertEquals(0L, ResourceEstimate.UNKNOWN.estimatedCpuTimeMicros());
    assertEquals(0L, ResourceEstimate.UNKNOWN.estimatedMemoryBytes());

    assertThrows(IllegalArgumentException.class,
        () -> new ResourceEstimate(-1L, 0L));
    assertThrows(IllegalArgumentException.class,
        () -> new ResourceEstimate(0L, -1L));
  }

  @Test
  @DisplayName("Default supports(...) requires exact id+algorithm match")
  void defaultSupportsMatchesExactly() {
    FakePasswordHashProvider p = new FakePasswordHashProvider();
    assertTrue(p.supports(
        FakePasswordHashProvider.PROVIDER_ID,
        FakePasswordHashProvider.ALGORITHM));
    assertFalse(p.supports(
        FakePasswordHashProvider.PROVIDER_ID, "Other"));
    assertFalse(p.supports(
        "other-provider", FakePasswordHashProvider.ALGORITHM));
  }
}
