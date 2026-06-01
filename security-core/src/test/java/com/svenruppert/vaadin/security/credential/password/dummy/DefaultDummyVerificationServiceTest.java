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
package com.svenruppert.vaadin.security.credential.password.dummy;

import com.svenruppert.vaadin.security.credential.password.envelope.PasswordHashCodec;
import com.svenruppert.vaadin.security.credential.password.pbkdf2.Pbkdf2ParameterNames;
import com.svenruppert.vaadin.security.credential.password.pbkdf2.Pbkdf2PasswordHashProvider;
import com.svenruppert.vaadin.security.credential.password.policy.DefaultPasswordHashPolicy;
import com.svenruppert.vaadin.security.credential.password.policy.PasswordHashPolicy;
import com.svenruppert.vaadin.security.credential.password.provider.PasswordHashProviderRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DefaultDummyVerificationServiceTest {

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
        .policyVersion(1)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, defaults)
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, min)
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, max)
        .build();
  }

  @Test
  @DisplayName("Construction caches a dummy envelope by running a real KDF")
  void constructionCachesEnvelope() {
    PasswordHashProviderRegistry registry = new PasswordHashProviderRegistry(
        List.of(new Pbkdf2PasswordHashProvider()));
    DefaultDummyVerificationService service = new DefaultDummyVerificationService(
        registry, fastTestPolicy(), PasswordHashCodec.DEFAULT);
    assertNotNull(service);
  }

  @Test
  @DisplayName("runDummyKdf never throws for any context value")
  void runDummyKdfNeverThrowsForAnyContext() {
    PasswordHashProviderRegistry registry = new PasswordHashProviderRegistry(
        List.of(new Pbkdf2PasswordHashProvider()));
    DefaultDummyVerificationService service = new DefaultDummyVerificationService(
        registry, fastTestPolicy(), PasswordHashCodec.DEFAULT);
    for (DummyVerificationContext c : DummyVerificationContext.values()) {
      service.runDummyKdf("any".toCharArray(), c);
    }
  }

  @Test
  @DisplayName("Constructor rejects an empty provider registry")
  void emptyRegistryRejected() {
    PasswordHashProviderRegistry empty = new PasswordHashProviderRegistry(List.of());
    assertThrows(IllegalStateException.class,
        () -> new DefaultDummyVerificationService(
            empty, fastTestPolicy(), PasswordHashCodec.DEFAULT));
  }
}
