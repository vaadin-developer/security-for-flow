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
package eu.jsentinel.jcustos.credential.password.policy;

import eu.jsentinel.jcustos.credential.CredentialType;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashEnvelope;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashFormatVersion;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2Defaults;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterValidator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertSame;

class DefaultPasswordHashValidatorTest {

  private final PasswordHashParameterValidatorRegistry registry =
      new PasswordHashParameterValidatorRegistry(List.of(
          new Pbkdf2ParameterValidator()));
  private final PasswordHashValidator validator =
      new DefaultPasswordHashValidator(registry);
  private final PasswordHashPolicy policy = Pbkdf2Defaults.referencePolicy();

  private static String saltOfLength(int n) {
    byte[] b = new byte[n];
    for (int i = 0; i < n; i++) b[i] = (byte) i;
    return Base64.getEncoder().encodeToString(b);
  }

  private PasswordHashEnvelope envelope(Map<String, String> params) {
    return new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1,
        CredentialType.PASSWORD,
        Pbkdf2ParameterNames.ALGORITHM,
        Pbkdf2ParameterNames.PROVIDER_ID,
        1,
        Optional.empty(),
        params,
        "ZGVyaXZlZA=="
    );
  }

  private Map<String, String> validParams() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(Pbkdf2ParameterNames.ITERATIONS,
        Integer.toString(Pbkdf2Defaults.DEFAULT_ITERATIONS));
    m.put(Pbkdf2ParameterNames.KEY_LENGTH,
        Integer.toString(Pbkdf2Defaults.DEFAULT_KEY_LENGTH));
    m.put(Pbkdf2ParameterNames.SALT,
        saltOfLength(Pbkdf2Defaults.DEFAULT_SALT_LENGTH));
    return m;
  }

  @Test
  @DisplayName("Valid PBKDF2 envelope passes validation")
  void validEnvelopeAccepted() {
    ValidatedPasswordHash result = validator.validate(
        envelope(validParams()), policy);
    assertNotNull(result);
    assertSame(policy, result.validatedAgainst());
  }

  @Test
  @DisplayName("Iterations below the configured minimum are rejected")
  void iterationsBelowMinimumRejected() {
    Map<String, String> params = validParams();
    params.put(Pbkdf2ParameterNames.ITERATIONS,
        Integer.toString(Pbkdf2Defaults.MIN_ITERATIONS - 1));
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(envelope(params), policy));
  }

  @Test
  @DisplayName("Iterations above the configured maximum are rejected before any KDF")
  void iterationsAboveMaximumRejected() {
    Map<String, String> params = validParams();
    params.put(Pbkdf2ParameterNames.ITERATIONS,
        Integer.toString(Pbkdf2Defaults.MAX_ITERATIONS + 1));
    PasswordHashValidationException ex = assertThrows(
        PasswordHashValidationException.class,
        () -> validator.validate(envelope(params), policy));
    assertEquals("pbkdf2 parameter above maximum: i", ex.getMessage());
  }

  @Test
  @DisplayName("Salt length below minimum is rejected")
  void saltBelowMinimumRejected() {
    Map<String, String> params = validParams();
    params.put(Pbkdf2ParameterNames.SALT,
        saltOfLength(Pbkdf2Defaults.MIN_SALT_LENGTH - 1));
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(envelope(params), policy));
  }

  @Test
  @DisplayName("Salt length above maximum is rejected")
  void saltAboveMaximumRejected() {
    Map<String, String> params = validParams();
    params.put(Pbkdf2ParameterNames.SALT,
        saltOfLength(Pbkdf2Defaults.MAX_SALT_LENGTH + 1));
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(envelope(params), policy));
  }

  @Test
  @DisplayName("Non-base64 salt fails parameter validation")
  void nonBase64SaltRejected() {
    Map<String, String> params = validParams();
    params.put(Pbkdf2ParameterNames.SALT, "@@@@@");
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(envelope(params), policy));
  }

  @Test
  @DisplayName("Unknown algorithm is rejected")
  void unknownAlgorithmRejected() {
    PasswordHashEnvelope env = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1,
        CredentialType.PASSWORD,
        "Argon2id",
        "argon2-bc",
        1,
        Optional.empty(),
        validParams(),
        "ZGVyaXZlZA=="
    );
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(env, policy));
  }

  @Test
  @DisplayName("Provider acceptability is left to the rehash engine, not the validator")
  void unknownProviderIsNotAValidatorConcern() {
    PasswordHashEnvelope env = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1,
        CredentialType.PASSWORD,
        Pbkdf2ParameterNames.ALGORITHM,
        "unknown-provider",
        1,
        Optional.empty(),
        validParams(),
        "ZGVyaXZlZA=="
    );
    // Validator accepts; the pipeline then asks the registry to resolve
    // the provider id and decides UNKNOWN_PROVIDER vs. PROVIDER_DEPRECATED.
    assertNotNull(validator.validate(env, policy));
  }

  @Test
  @DisplayName("Envelope newer than the active policy version is rejected")
  void newerEnvelopePolicyVersionRejected() {
    PasswordHashEnvelope env = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1,
        CredentialType.PASSWORD,
        Pbkdf2ParameterNames.ALGORITHM,
        Pbkdf2ParameterNames.PROVIDER_ID,
        2,
        Optional.empty(),
        validParams(),
        "ZGVyaXZlZA=="
    );
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(env, policy));
  }

  @Test
  @DisplayName("Algorithm without a registered parameter validator is rejected")
  void algorithmWithoutValidatorRejected() {
    PasswordHashParameterValidatorRegistry empty =
        new PasswordHashParameterValidatorRegistry(List.of());
    PasswordHashValidator validatorNoPbkdf2 =
        new DefaultPasswordHashValidator(empty);
    assertThrows(PasswordHashValidationException.class,
        () -> validatorNoPbkdf2.validate(envelope(validParams()), policy));
  }

  @Test
  @DisplayName("Missing iterations parameter is rejected before KDF would run")
  void missingIterationsRejectedBeforeAnyExpensiveWork() {
    Map<String, String> params = validParams();
    params.remove(Pbkdf2ParameterNames.ITERATIONS);
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(envelope(params), policy));
  }

  @Test
  @DisplayName("Registry rejects duplicate validators for the same algorithm")
  void registryRejectsDuplicateValidators() {
    assertThrows(IllegalArgumentException.class,
        () -> new PasswordHashParameterValidatorRegistry(List.of(
            new Pbkdf2ParameterValidator(),
            new Pbkdf2ParameterValidator())));
  }
}
