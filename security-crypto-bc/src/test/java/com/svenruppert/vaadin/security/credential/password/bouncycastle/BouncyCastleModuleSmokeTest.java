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
package com.svenruppert.vaadin.security.credential.password.bouncycastle;

import com.svenruppert.vaadin.security.credential.password.PasswordHashingService;
import com.svenruppert.vaadin.security.credential.password.PasswordHashingServices;
import com.svenruppert.vaadin.security.credential.password.pbkdf2.Pbkdf2ParameterNames;
import com.svenruppert.vaadin.security.credential.password.policy.DefaultPasswordHashPolicy;
import com.svenruppert.vaadin.security.credential.password.policy.PasswordHashPolicy;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BouncyCastleModuleSmokeTest {

  @Test
  @DisplayName("BouncyCastle bcprov is on the test classpath")
  void bouncyCastleIsAvailable() {
    assertNotNull(Argon2BytesGenerator.class,
        "bcprov must be resolvable when this module is built");
  }

  @Test
  @DisplayName("Loading the module does not change the global JCA provider order")
  void globalProviderOrderUntouched() {
    Provider[] before = Security.getProviders();
    String[] beforeNames = Arrays.stream(before)
        .map(Provider::getName).toArray(String[]::new);

    // Reference a few classes from this module and from bcprov.
    assertNotNull(BouncyCastleModuleInfo.MODULE_ID);
    assertNotNull(Argon2BytesGenerator.class);

    Provider[] after = Security.getProviders();
    String[] afterNames = Arrays.stream(after)
        .map(Provider::getName).toArray(String[]::new);
    assertArrayEquals(beforeNames, afterNames,
        "no module class may install a JCA provider as a side effect");
  }

  @Test
  @DisplayName("Module identity constants are stable and unique")
  void moduleIdentity() {
    assertEquals("security-crypto-bc", BouncyCastleModuleInfo.MODULE_ID);
    assertEquals("argon2id-bc", BouncyCastleModuleInfo.ARGON2ID_PROVIDER_ID);
    assertEquals("bcrypt-bc", BouncyCastleModuleInfo.BCRYPT_PROVIDER_ID);
    assertEquals("scrypt-bc", BouncyCastleModuleInfo.SCRYPT_PROVIDER_ID);
    assertEquals("Argon2id", BouncyCastleModuleInfo.ARGON2ID_ALGORITHM);
    assertEquals("bcrypt", BouncyCastleModuleInfo.BCRYPT_ALGORITHM);
    assertEquals("scrypt", BouncyCastleModuleInfo.SCRYPT_ALGORITHM);
  }

  @Test
  @DisplayName("Requesting a modern profile without a registered provider fails fast")
  void modernProfileFailsFastWhenProviderMissing() {
    // Build a policy that prefers Argon2id even though no Argon2id
    // provider is registered yet (the implementation arrives in Prompt
    // 010). The pipeline must refuse to start instead of silently
    // falling back to PBKDF2.
    PasswordHashPolicy modernPolicy = DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(BouncyCastleModuleInfo.ARGON2ID_ALGORITHM)
        .preferredProviderId(BouncyCastleModuleInfo.ARGON2ID_PROVIDER_ID)
        .defaultParameters(BouncyCastleModuleInfo.ARGON2ID_ALGORITHM,
            java.util.Map.of("t", "3", "m", "65536", "p", "1"))
        .minimumParameters(BouncyCastleModuleInfo.ARGON2ID_ALGORITHM,
            java.util.Map.of("t", "1", "m", "8192", "p", "1"))
        .maximumParameters(BouncyCastleModuleInfo.ARGON2ID_ALGORITHM,
            java.util.Map.of("t", "10", "m", "1048576", "p", "8"))
        .build();

    IllegalStateException ex = assertThrows(IllegalStateException.class,
        () -> PasswordHashingServices.defaults(modernPolicy));
    assertTrue(ex.getMessage().toLowerCase().contains("provider"),
        "fail-fast message must reference the missing provider, was: "
            + ex.getMessage());
  }

  @Test
  @DisplayName("Fallback to the PBKDF2 reference policy still works through this module")
  void pbkdf2ReferencePolicyStillWorks() {
    PasswordHashingService service = PasswordHashingServices.defaults();
    assertNotNull(service);
    // Light sanity check: a hash + verify round trip with a small policy
    // would already be covered by security-core; we only assert that
    // the wiring helper is reachable when the BC module is on the path.
    assertEquals(Pbkdf2ParameterNames.PROVIDER_ID,
        com.svenruppert.vaadin.security.credential.password.pbkdf2.Pbkdf2Defaults
            .referencePolicy().preferredProviderId());
  }
}
