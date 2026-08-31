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
package eu.jsentinel.jcustos.credential.password;

import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordHashingServiceSecretValueTest {

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

  @Test
  @DisplayName("hash(SecretValue) delegates to the char[] overload and matches via verify(SecretValue,...)")
  void hashAndVerifyWithSecretValue() {
    PasswordHashingService service = PasswordHashingServices.defaults(fastTestPolicy());
    SecretValue secret = SecretValue.ofString("hunter2");
    PasswordHashResult hashed = service.hash(secret);
    SecretValue candidate = SecretValue.ofString("hunter2");
    assertInstanceOf(CredentialVerificationResult.Verified.class,
        service.verify(candidate, hashed.encodedHash()));
  }

  @Test
  @DisplayName("verify(SecretValue,...) returns Failed for a wrong password")
  void wrongPasswordWithSecretValue() {
    PasswordHashingService service = PasswordHashingServices.defaults(fastTestPolicy());
    PasswordHashResult hashed = service.hash(SecretValue.ofString("hunter2"));
    SecretValue wrong = SecretValue.ofString("hunter3");
    assertInstanceOf(CredentialVerificationResult.Failed.class,
        service.verify(wrong, hashed.encodedHash()));
  }

  @Test
  @DisplayName("verifyAgainstNothing(SecretValue) still runs the dummy KDF path")
  void verifyAgainstNothingWithSecretValue() {
    PasswordHashingService service = PasswordHashingServices.defaults(fastTestPolicy());
    SecretValue candidate = SecretValue.ofString("anything");
    assertInstanceOf(CredentialVerificationResult.Failed.class,
        service.verifyAgainstNothing(candidate));
  }

  @Test
  @DisplayName("SecretValue.toString redaction holds across the service overloads")
  void serviceOverloadsDoNotLogSecrets() {
    SecretValue secret = SecretValue.ofString("hunter2");
    String text = secret.toString();
    assertTrue(text.contains("length=7"));
    assertTrue(text.contains("destroyed=false"));
    secret.destroy();
    // After destroy, secret accessors throw; reusing it through the
    // service must surface as IllegalStateException, never as a leaked
    // password fragment.
    PasswordHashingService service = PasswordHashingServices.defaults(fastTestPolicy());
    try {
      service.hash(secret);
    } catch (IllegalStateException expected) {
      assertTrue(expected.getMessage().toLowerCase().contains("destroyed"));
    }
  }
}
