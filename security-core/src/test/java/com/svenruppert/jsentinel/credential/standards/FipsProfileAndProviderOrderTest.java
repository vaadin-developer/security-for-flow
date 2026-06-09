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
package com.svenruppert.jsentinel.credential.standards;

import com.svenruppert.jsentinel.credential.password.PasswordHashingService;
import com.svenruppert.jsentinel.credential.password.PasswordHashingServices;
import com.svenruppert.jsentinel.credential.password.limiter.NoLimitKdfExecutionLimiter;
import com.svenruppert.jsentinel.credential.password.pbkdf2.Pbkdf2ParameterNames;
import com.svenruppert.jsentinel.credential.password.policy.DefaultPasswordHashPolicy;
import com.svenruppert.jsentinel.credential.password.policy.PasswordHashPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FipsProfileAndProviderOrderTest {

  @Test
  @DisplayName("FipsProfile.permissive allows every optional algorithm module")
  void permissiveAllowsEverything() {
    FipsProfile p = FipsProfile.permissive();
    assertFalse(p.strictMode());
    assertTrue(p.allowsArgon2());
    assertTrue(p.allowsBcrypt());
    assertTrue(p.allowsScrypt());
    assertTrue(p.allowsHibpSha1Prefix());
  }

  @Test
  @DisplayName("FipsProfile.strict forbids non-FIPS algorithm modules and SHA-1 prefix")
  void strictForbidsNonFipsAlgorithms() {
    FipsProfile p = FipsProfile.strict();
    assertTrue(p.strictMode());
    assertFalse(p.allowsArgon2());
    assertFalse(p.allowsBcrypt());
    assertFalse(p.allowsScrypt());
    assertFalse(p.allowsHibpSha1Prefix());
  }

  @Test
  @DisplayName("FipsProfile is a value record: equality respects every component")
  void valueEquality() {
    assertEquals(FipsProfile.strict(), FipsProfile.strict());
    assertEquals(FipsProfile.permissive(), FipsProfile.permissive());
    assertFalse(FipsProfile.strict().equals(FipsProfile.permissive()));
  }

  @Test
  @DisplayName("Constructing the default PasswordHashingService never alters JCA provider order")
  void buildingTheServiceDoesNotTouchProviderOrder() {
    Provider[] before = Security.getProviders();
    String[] beforeNames = Arrays.stream(before)
        .map(Provider::getName).toArray(String[]::new);
    PasswordHashingService svc = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE);
    assertNotNull(svc);
    Provider[] after = Security.getProviders();
    String[] afterNames = Arrays.stream(after)
        .map(Provider::getName).toArray(String[]::new);
    assertArrayEqualsByName(beforeNames, afterNames);
  }

  @Test
  @DisplayName("Hashing a password never alters JCA provider order")
  void hashingDoesNotTouchProviderOrder() {
    PasswordHashingService svc = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE);
    String[] before = providerNames();
    svc.hash("hunter222".toCharArray());
    String[] after = providerNames();
    assertArrayEqualsByName(before, after);
  }

  @Test
  @DisplayName("Class loading of FipsProfile does not register a JCA provider")
  void loadingFipsProfileDoesNotRegisterProvider() {
    String[] before = providerNames();
    FipsProfile.strict();
    FipsProfile.permissive();
    String[] after = providerNames();
    assertArrayEqualsByName(before, after);
  }

  private static String[] providerNames() {
    return Arrays.stream(Security.getProviders())
        .map(Provider::getName).toArray(String[]::new);
  }

  private static void assertArrayEqualsByName(String[] before, String[] after) {
    if (!Arrays.equals(before, after)) {
      throw new AssertionError(
          "JCA provider order changed: was " + Arrays.toString(before)
              + ", now " + Arrays.toString(after));
    }
  }

  private static PasswordHashPolicy fastTestPolicy() {
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
        .policyVersion(1)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, defaults)
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, min)
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, max)
        .build();
  }
}
