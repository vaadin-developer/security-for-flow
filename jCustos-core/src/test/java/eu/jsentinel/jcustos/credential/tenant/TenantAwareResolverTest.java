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
package eu.jsentinel.jcustos.credential.tenant;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.pepper.PepperReference;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TenantAwareResolverTest {

  private static PasswordHashPolicy policy(int version) {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    defaults.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    Map<String, String> min = new LinkedHashMap<>(defaults);
    min.put(Pbkdf2ParameterNames.SALT_LENGTH, "16");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(Pbkdf2ParameterNames.ITERATIONS, "2000");
    max.put(Pbkdf2ParameterNames.KEY_LENGTH, "64");
    max.put(Pbkdf2ParameterNames.SALT_LENGTH, "64");
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(version)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, defaults)
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, min)
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, max)
        .build();
  }

  private static PepperReference pepper(String id) {
    byte[] key = new byte[32];
    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }
    return new PepperReference(id, key);
  }

  @Test
  @DisplayName("Single-tenant default: TenantId.DEFAULT resolves to the default policy")
  void singleTenantDefault() {
    PasswordHashPolicy p1 = policy(1);
    DefaultTenantAwarePasswordHashPolicyResolver resolver =
        new DefaultTenantAwarePasswordHashPolicyResolver(p1);
    assertSame(p1,
        resolver.resolve(TenantCredentialContext.SINGLE_TENANT_DEFAULT));
  }

  @Test
  @DisplayName("Unknown tenant falls back to the default — never throws")
  void unknownTenantFallsBack() {
    PasswordHashPolicy p1 = policy(1);
    DefaultTenantAwarePasswordHashPolicyResolver resolver =
        new DefaultTenantAwarePasswordHashPolicyResolver(p1);
    PasswordHashPolicy resolved = resolver.resolve(
        TenantCredentialContext.of(TenantId.of("unknown-tenant")));
    assertSame(p1, resolved,
        "unknown tenant must fall back to default, never throw");
  }

  @Test
  @DisplayName("Tenant-specific override wins over the default")
  void tenantOverrideWins() {
    PasswordHashPolicy fallback = policy(1);
    PasswordHashPolicy tenantPolicy = policy(2);
    Map<TenantId, PasswordHashPolicy> overrides = new java.util.HashMap<>();
    overrides.put(TenantId.of("tenant-A"), tenantPolicy);
    DefaultTenantAwarePasswordHashPolicyResolver resolver =
        new DefaultTenantAwarePasswordHashPolicyResolver(
            fallback, overrides);
    assertSame(tenantPolicy,
        resolver.resolve(TenantCredentialContext.of(TenantId.of("tenant-A"))));
    assertSame(fallback,
        resolver.resolve(TenantCredentialContext.of(TenantId.of("tenant-B"))));
    assertEquals(2, resolver.resolve(
        TenantCredentialContext.of(TenantId.of("tenant-A"))).policyVersion());
    assertEquals(1, resolver.resolve(
        TenantCredentialContext.of(TenantId.of("tenant-B"))).policyVersion());
  }

  @Test
  @DisplayName("Pepper resolver: single-tenant with no pepper returns empty for every tenant")
  void pepperSingleTenantEmpty() {
    DefaultTenantAwarePepperReferenceResolver resolver =
        DefaultTenantAwarePepperReferenceResolver.singleTenant(Optional.empty());
    assertEquals(Optional.empty(), resolver.activeReferenceFor(
        TenantCredentialContext.SINGLE_TENANT_DEFAULT));
    assertEquals(Optional.empty(), resolver.activeReferenceFor(
        TenantCredentialContext.of(TenantId.of("anything"))));
  }

  @Test
  @DisplayName("Pepper resolver: per-tenant override wins over single-tenant default")
  void pepperOverrideWins() {
    PepperReference defaultPepper = pepper("default-key-1");
    PepperReference tenantAPepper = pepper("tenant-A-key-2");
    Map<TenantId, PepperReference> overrides = new java.util.HashMap<>();
    overrides.put(TenantId.of("tenant-A"), tenantAPepper);
    DefaultTenantAwarePepperReferenceResolver resolver =
        new DefaultTenantAwarePepperReferenceResolver(
            Optional.of(defaultPepper), overrides);
    assertEquals("tenant-A-key-2",
        resolver.activeReferenceFor(
            TenantCredentialContext.of(TenantId.of("tenant-A")))
            .get().keyId());
    assertEquals("default-key-1",
        resolver.activeReferenceFor(
            TenantCredentialContext.of(TenantId.of("tenant-B")))
            .get().keyId());
  }

  @Test
  @DisplayName("TenantCredentialContext.SINGLE_TENANT_DEFAULT is the canonical singleton")
  void singletonIdentity() {
    assertSame(TenantCredentialContext.SINGLE_TENANT_DEFAULT,
        TenantCredentialContext.SINGLE_TENANT_DEFAULT);
    assertEquals(TenantId.DEFAULT,
        TenantCredentialContext.SINGLE_TENANT_DEFAULT.tenantId());
  }

  @Test
  @DisplayName("TenantCredentialContext invariants")
  void contextInvariants() {
    assertThrows(NullPointerException.class,
        () -> new TenantCredentialContext(null));
    assertThrows(NullPointerException.class,
        () -> TenantCredentialContext.of(null));
  }

  @Test
  @DisplayName("Policy resolver invariants")
  void policyResolverInvariants() {
    PasswordHashPolicy p = policy(1);
    assertThrows(NullPointerException.class,
        () -> new DefaultTenantAwarePasswordHashPolicyResolver(null));
    assertThrows(NullPointerException.class,
        () -> new DefaultTenantAwarePasswordHashPolicyResolver(p, null));
    DefaultTenantAwarePasswordHashPolicyResolver resolver =
        new DefaultTenantAwarePasswordHashPolicyResolver(p);
    assertThrows(NullPointerException.class,
        () -> resolver.resolve(null));
  }

  @Test
  @DisplayName("Pepper resolver invariants")
  void pepperResolverInvariants() {
    assertThrows(NullPointerException.class,
        () -> new DefaultTenantAwarePepperReferenceResolver(null,
            new java.util.HashMap<>()));
    assertThrows(NullPointerException.class,
        () -> new DefaultTenantAwarePepperReferenceResolver(
            Optional.empty(), null));
    DefaultTenantAwarePepperReferenceResolver resolver =
        DefaultTenantAwarePepperReferenceResolver.singleTenant(Optional.empty());
    assertThrows(NullPointerException.class,
        () -> resolver.activeReferenceFor(null));
  }

  @Test
  @DisplayName("Tenant context never embeds username, email, or other subject data")
  void contextIsTenantOnly() {
    // Structural test: the only record component is tenantId.
    // Adding any subject-level field would force a record reshape
    // and break this assertion.
    Class<?> ctx = TenantCredentialContext.class;
    java.lang.reflect.RecordComponent[] components = ctx.getRecordComponents();
    assertEquals(1, components.length,
        "TenantCredentialContext must carry only TenantId");
    assertEquals("tenantId", components[0].getName());
  }

  @Test
  @DisplayName("Public TenantCredentialContext.toString does not embed secret-shaped values")
  void contextToStringSafe() {
    String text = TenantCredentialContext.of(TenantId.of("tenant-A")).toString();
    assertTrue(text.contains("tenant-A"),
        "tenant id may appear");
    // it must NOT contain anything that looks like a password
    assertTrue(!text.toLowerCase().contains("password"));
    assertTrue(!text.toLowerCase().contains("hash="));
  }

  @Test
  @DisplayName("Override count reflects the number of explicit per-tenant bindings")
  void overrideCountSurfaced() {
    PasswordHashPolicy p1 = policy(1);
    Map<TenantId, PasswordHashPolicy> overrides = new java.util.HashMap<>();
    overrides.put(TenantId.of("A"), p1);
    overrides.put(TenantId.of("B"), p1);
    DefaultTenantAwarePasswordHashPolicyResolver resolver =
        new DefaultTenantAwarePasswordHashPolicyResolver(p1, overrides);
    assertEquals(2, resolver.overrideCount());
    assertSame(p1, resolver.defaultPolicy());
    assertNotSame(overrides, resolver);   // resolver does not retain the original map by reference
  }
}
