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
package com.svenruppert.jsentinel.credential.password.policy;

import com.svenruppert.jsentinel.credential.CredentialType;
import com.svenruppert.jsentinel.credential.password.envelope.PasswordHashEnvelope;
import com.svenruppert.jsentinel.credential.password.envelope.PasswordHashFormatVersion;
import com.svenruppert.jsentinel.credential.password.pbkdf2.Pbkdf2Defaults;
import com.svenruppert.jsentinel.credential.password.pbkdf2.Pbkdf2ParameterNames;
import com.svenruppert.jsentinel.credential.password.pbkdf2.Pbkdf2ParameterValidator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyRejectedVersionsTest {

  private static String saltOfLength(int n) {
    byte[] b = new byte[n];
    for (int i = 0; i < n; i++) b[i] = (byte) i;
    return Base64.getEncoder().encodeToString(b);
  }

  private static Map<String, String> validParams() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(Pbkdf2ParameterNames.ITERATIONS,
        Integer.toString(Pbkdf2Defaults.DEFAULT_ITERATIONS));
    m.put(Pbkdf2ParameterNames.KEY_LENGTH,
        Integer.toString(Pbkdf2Defaults.DEFAULT_KEY_LENGTH));
    m.put(Pbkdf2ParameterNames.SALT,
        saltOfLength(Pbkdf2Defaults.DEFAULT_SALT_LENGTH));
    return m;
  }

  private static PasswordHashEnvelope envelope(int policyVersion) {
    return new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1,
        CredentialType.PASSWORD,
        Pbkdf2ParameterNames.ALGORITHM,
        Pbkdf2ParameterNames.PROVIDER_ID,
        policyVersion,
        Optional.empty(),
        validParams(),
        "ZGVyaXZlZA==");
  }

  @Test
  @DisplayName("Default policy has no rejected format or policy versions")
  void defaultsAreEmpty() {
    PasswordHashPolicy policy = Pbkdf2Defaults.referencePolicy();
    assertTrue(policy.rejectedFormatVersions().isEmpty());
    assertTrue(policy.rejectedPolicyVersions().isEmpty());
  }

  @Test
  @DisplayName("Rejected policy version is refused by the validator")
  void rejectedPolicyVersionRefused() {
    PasswordHashPolicy policy = DefaultPasswordHashPolicy.builder()
        .policyVersion(5)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM,
            Pbkdf2Defaults.defaultParameters())
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM,
            Pbkdf2Defaults.minimumParameters())
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM,
            Pbkdf2Defaults.maximumParameters())
        .rejectPolicyVersion(2)
        .build();
    DefaultPasswordHashValidator validator = new DefaultPasswordHashValidator(
        new PasswordHashParameterValidatorRegistry(
            List.of(new Pbkdf2ParameterValidator())));

    // version 1 still accepted (older but not rejected) → flagged for rehash later
    assertEquals(envelope(1), validator.validate(envelope(1), policy).envelope());
    assertEquals(envelope(3), validator.validate(envelope(3), policy).envelope());
    // version 2 is rejected outright
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(envelope(2), policy));
  }

  @Test
  @DisplayName("Rejected format version is refused by the validator")
  void rejectedFormatVersionRefused() {
    // Build a policy that rejects the only known format version. This
    // is a contrived configuration but exercises the rejection path
    // without needing a future V2 wire value.
    PasswordHashPolicy policy = DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM,
            Pbkdf2Defaults.defaultParameters())
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM,
            Pbkdf2Defaults.minimumParameters())
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM,
            Pbkdf2Defaults.maximumParameters())
        .rejectFormatVersion(PasswordHashFormatVersion.V1.wireValue())
        .build();
    DefaultPasswordHashValidator validator = new DefaultPasswordHashValidator(
        new PasswordHashParameterValidatorRegistry(
            List.of(new Pbkdf2ParameterValidator())));
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(envelope(1), policy));
  }

  @Test
  @DisplayName("rejectedFormatVersions / rejectedPolicyVersions exposed are unmodifiable")
  void exposedSetsAreUnmodifiable() {
    PasswordHashPolicy policy = DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM,
            Pbkdf2Defaults.defaultParameters())
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM,
            Pbkdf2Defaults.minimumParameters())
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM,
            Pbkdf2Defaults.maximumParameters())
        .rejectFormatVersion(99)
        .rejectPolicyVersion(7)
        .build();
    assertThrows(UnsupportedOperationException.class,
        () -> policy.rejectedFormatVersions().add(123));
    assertThrows(UnsupportedOperationException.class,
        () -> policy.rejectedPolicyVersions().add(123));
    assertEquals(1, policy.rejectedFormatVersions().size());
    assertEquals(1, policy.rejectedPolicyVersions().size());
  }
}
