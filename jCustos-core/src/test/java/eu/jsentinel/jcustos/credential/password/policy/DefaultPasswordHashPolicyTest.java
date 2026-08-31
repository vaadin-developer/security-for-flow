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
package eu.jsentinel.jcustos.credential.password.policy;

import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashFormatVersion;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2Defaults;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultPasswordHashPolicyTest {

  @Test
  @DisplayName("Reference PBKDF2 policy is internally consistent")
  void referencePolicyIsConsistent() {
    PasswordHashPolicy policy = Pbkdf2Defaults.referencePolicy();

    assertEquals(1, policy.policyVersion());
    assertEquals(PasswordHashFormatVersion.CURRENT,
        policy.preferredFormatVersion());
    assertEquals(Pbkdf2ParameterNames.ALGORITHM, policy.preferredAlgorithm());
    assertEquals(Pbkdf2ParameterNames.PROVIDER_ID, policy.preferredProviderId());
    assertTrue(policy.isAlgorithmAcceptable(Pbkdf2ParameterNames.ALGORITHM));
    assertTrue(policy.isProviderAcceptable(Pbkdf2ParameterNames.PROVIDER_ID));
    assertFalse(policy.isAlgorithmAcceptable("Argon2id"));
    assertFalse(policy.isProviderAcceptable("argon2-bc"));
  }

  @Test
  @DisplayName("Policy returns unmodifiable parameter maps")
  void parameterMapsAreUnmodifiable() {
    PasswordHashPolicy policy = Pbkdf2Defaults.referencePolicy();
    Map<String, String> defaults = policy.defaultParameters(
        Pbkdf2ParameterNames.ALGORITHM);

    assertThrows(UnsupportedOperationException.class,
        () -> defaults.put("evil", "value"));
  }

  @Test
  @DisplayName("Builder rejects a preferred algorithm without bounds")
  void builderRejectsIncompletePolicy() {
    assertThrows(IllegalArgumentException.class, () ->
        DefaultPasswordHashPolicy.builder()
            .preferredAlgorithm("PBKDF2WithHmacSHA256")
            .preferredProviderId("pbkdf2-jdk")
            .build());
  }

  @Test
  @DisplayName("Policy throws PasswordHashValidationException for unknown algorithm")
  void unknownAlgorithmThrows() {
    PasswordHashPolicy policy = Pbkdf2Defaults.referencePolicy();
    assertThrows(PasswordHashValidationException.class,
        () -> policy.defaultParameters("Argon2id"));
    assertThrows(PasswordHashValidationException.class,
        () -> policy.minimumParameters("Argon2id"));
    assertThrows(PasswordHashValidationException.class,
        () -> policy.maximumParameters("Argon2id"));
  }

  @Test
  @DisplayName("Builder rejects a non-positive policyVersion")
  void builderRejectsNonPositiveVersion() {
    assertThrows(IllegalArgumentException.class, () ->
        DefaultPasswordHashPolicy.builder()
            .policyVersion(0)
            .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
            .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
            .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, Pbkdf2Defaults.defaultParameters())
            .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, Pbkdf2Defaults.minimumParameters())
            .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, Pbkdf2Defaults.maximumParameters())
            .build());
  }
}
