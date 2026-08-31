/*-
 * #%L
 * Security Crypto — BouncyCastle
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
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
package eu.jsentinel.jcustos.credential.password.bouncycastle;

import eu.jsentinel.jcustos.credential.InternalAuditEventType;
import eu.jsentinel.jcustos.credential.PublicFailureType;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.password.RehashDecision;
import eu.jsentinel.jcustos.credential.password.RehashReason;
import eu.jsentinel.jcustos.credential.password.bouncycastle.argon2.Argon2idDefaults;
import eu.jsentinel.jcustos.credential.password.bouncycastle.argon2.Argon2idParameterNames;
import eu.jsentinel.jcustos.credential.password.bouncycastle.bcrypt.BcryptParameterNames;
import eu.jsentinel.jcustos.credential.password.bouncycastle.scrypt.ScryptDefaults;
import eu.jsentinel.jcustos.credential.password.bouncycastle.scrypt.ScryptParameterNames;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProviderRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ModernProfileIntegrationTest {

  /**
   * A modern policy with lower iteration counts so the integration
   * tests stay fast. Identical to the reference policy in structure,
   * only the bounds are tighter for time. Mirrors operator-tunable
   * deployments.
   */
  private static PasswordHashPolicy fastModernPolicy() {
    Map<String, String> argonDefaults = new LinkedHashMap<>();
    argonDefaults.put(Argon2idParameterNames.ITERATIONS, "1");
    argonDefaults.put(Argon2idParameterNames.MEMORY_KIB, "8192");
    argonDefaults.put(Argon2idParameterNames.PARALLELISM, "1");
    argonDefaults.put(Argon2idParameterNames.HASH_LENGTH, "32");
    Map<String, String> argonMin = new LinkedHashMap<>(argonDefaults);
    argonMin.put(Argon2idParameterNames.SALT_LENGTH, "16");
    Map<String, String> argonMax = new LinkedHashMap<>();
    argonMax.put(Argon2idParameterNames.ITERATIONS, "5");
    argonMax.put(Argon2idParameterNames.MEMORY_KIB, "65536");
    argonMax.put(Argon2idParameterNames.PARALLELISM, "4");
    argonMax.put(Argon2idParameterNames.HASH_LENGTH, "64");
    argonMax.put(Argon2idParameterNames.SALT_LENGTH, "64");

    Map<String, String> pbkdf2Defaults = new LinkedHashMap<>();
    pbkdf2Defaults.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    pbkdf2Defaults.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    Map<String, String> pbkdf2Min = new LinkedHashMap<>(pbkdf2Defaults);
    pbkdf2Min.put(Pbkdf2ParameterNames.SALT_LENGTH, "16");
    Map<String, String> pbkdf2Max = new LinkedHashMap<>();
    pbkdf2Max.put(Pbkdf2ParameterNames.ITERATIONS, "2000");
    pbkdf2Max.put(Pbkdf2ParameterNames.KEY_LENGTH, "64");
    pbkdf2Max.put(Pbkdf2ParameterNames.SALT_LENGTH, "64");

    Map<String, String> bcryptDefaults = new LinkedHashMap<>();
    bcryptDefaults.put(BcryptParameterNames.COST, "4");
    Map<String, String> bcryptMin = new LinkedHashMap<>();
    bcryptMin.put(BcryptParameterNames.COST, "4");
    Map<String, String> bcryptMax = new LinkedHashMap<>();
    bcryptMax.put(BcryptParameterNames.COST, "6");

    Map<String, String> scryptDefaults = new LinkedHashMap<>();
    scryptDefaults.put(ScryptParameterNames.N, "1024");
    scryptDefaults.put(ScryptParameterNames.R, "8");
    scryptDefaults.put(ScryptParameterNames.P, "1");
    scryptDefaults.put(ScryptParameterNames.HASH_LENGTH, "32");
    Map<String, String> scryptMin = new LinkedHashMap<>();
    scryptMin.put(ScryptParameterNames.N, "512");
    scryptMin.put(ScryptParameterNames.R, "4");
    scryptMin.put(ScryptParameterNames.P, "1");
    scryptMin.put(ScryptParameterNames.HASH_LENGTH, "32");
    scryptMin.put(ScryptParameterNames.SALT_LENGTH, "16");
    Map<String, String> scryptMax = new LinkedHashMap<>();
    scryptMax.put(ScryptParameterNames.N, "2048");
    scryptMax.put(ScryptParameterNames.R, "16");
    scryptMax.put(ScryptParameterNames.P, "4");
    scryptMax.put(ScryptParameterNames.HASH_LENGTH, "64");
    scryptMax.put(ScryptParameterNames.SALT_LENGTH, "64");

    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(Argon2idParameterNames.ALGORITHM)
        .preferredProviderId(Argon2idParameterNames.PROVIDER_ID)
        .addAcceptableAlgorithm(BcryptParameterNames.ALGORITHM)
        .addAcceptableProviderId(BcryptParameterNames.PROVIDER_ID)
        .addAcceptableAlgorithm(ScryptParameterNames.ALGORITHM)
        .addAcceptableProviderId(ScryptParameterNames.PROVIDER_ID)
        .addAcceptableAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .addAcceptableProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Argon2idParameterNames.ALGORITHM, argonDefaults)
        .minimumParameters(Argon2idParameterNames.ALGORITHM, argonMin)
        .maximumParameters(Argon2idParameterNames.ALGORITHM, argonMax)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, pbkdf2Defaults)
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, pbkdf2Min)
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, pbkdf2Max)
        .defaultParameters(BcryptParameterNames.ALGORITHM, bcryptDefaults)
        .minimumParameters(BcryptParameterNames.ALGORITHM, bcryptMin)
        .maximumParameters(BcryptParameterNames.ALGORITHM, bcryptMax)
        .defaultParameters(ScryptParameterNames.ALGORITHM, scryptDefaults)
        .minimumParameters(ScryptParameterNames.ALGORITHM, scryptMin)
        .maximumParameters(ScryptParameterNames.ALGORITHM, scryptMax)
        .build();
  }

  @Test
  @DisplayName("modern() produces a fully wired Argon2id-preferred service")
  void modernIsWiredEndToEnd() {
    PasswordHashingService service = BouncyCastleHashingServices.modern(fastModernPolicy());
    assertNotNull(service);

    PasswordHashResult result = service.hash("hunter2".toCharArray());
    assertEquals(Argon2idParameterNames.ALGORITHM, result.algorithm());
    assertEquals(Argon2idParameterNames.PROVIDER_ID, result.providerId());
    assertTrue(result.encodedHash().startsWith("$pwh$v=1$"));
    assertTrue(result.encodedHash().contains("$alg=Argon2id$"));

    CredentialVerificationResult verified = service.verify(
        "hunter2".toCharArray(), result.encodedHash());
    assertInstanceOf(CredentialVerificationResult.Verified.class, verified);
    assertEquals(RehashDecision.NotRequired.INSTANCE,
        service.needsRehash(result.encodedHash()));
  }

  @Test
  @DisplayName("Wrong password under modern profile yields the generic failure")
  void wrongPasswordModernFailureIsGeneric() {
    PasswordHashingService service = BouncyCastleHashingServices.modern(fastModernPolicy());
    PasswordHashResult ok = service.hash("hunter2".toCharArray());
    CredentialVerificationResult.Failed failed = assertInstanceOf(
        CredentialVerificationResult.Failed.class,
        service.verify("hunter3".toCharArray(), ok.encodedHash()));
    assertEquals(PublicFailureType.INVALID_CREDENTIALS, failed.publicFailureType());
    assertEquals(InternalAuditEventType.VERIFICATION_FAILED_MISMATCH,
        failed.internalAuditEventType());
  }

  @Test
  @DisplayName("Stored PBKDF2 envelope under modern profile verifies and triggers ALGORITHM_DEPRECATED rehash")
  void pbkdf2EnvelopeMigratesToArgon2id() {
    PasswordHashingService coreService = PasswordHashingServices.defaults(
        coreOnlyPbkdf2Policy());
    PasswordHashResult coreHash = coreService.hash("hunter2".toCharArray());
    assertTrue(coreHash.encodedHash().contains("$alg=PBKDF2WithHmacSHA256$"));

    PasswordHashingService modern = BouncyCastleHashingServices.modern(fastModernPolicy());
    assertInstanceOf(CredentialVerificationResult.Verified.class,
        modern.verify("hunter2".toCharArray(), coreHash.encodedHash()));

    RehashDecision.Required required = assertInstanceOf(
        RehashDecision.Required.class,
        modern.needsRehash(coreHash.encodedHash()));
    assertEquals(RehashReason.ALGORITHM_DEPRECATED, required.reason());
  }

  @Test
  @DisplayName("Stored bcrypt envelope under modern profile verifies and triggers ALGORITHM_DEPRECATED rehash")
  void bcryptEnvelopeMigratesToArgon2id() {
    PasswordHashingService bcryptOnly = BouncyCastleHashingServices.modern(
        bcryptOnlyPolicy());
    PasswordHashResult bcryptHash = bcryptOnly.hash("hunter2".toCharArray());
    assertTrue(bcryptHash.encodedHash().contains("$alg=bcrypt$"));

    PasswordHashingService modern = BouncyCastleHashingServices.modern(fastModernPolicy());
    assertInstanceOf(CredentialVerificationResult.Verified.class,
        modern.verify("hunter2".toCharArray(), bcryptHash.encodedHash()));
    RehashDecision.Required required = assertInstanceOf(
        RehashDecision.Required.class,
        modern.needsRehash(bcryptHash.encodedHash()));
    assertEquals(RehashReason.ALGORITHM_DEPRECATED, required.reason());
  }

  @Test
  @DisplayName("Stored scrypt envelope under modern profile verifies and triggers ALGORITHM_DEPRECATED rehash")
  void scryptEnvelopeMigratesToArgon2id() {
    PasswordHashingService scryptOnly = BouncyCastleHashingServices.modern(
        scryptOnlyPolicy());
    PasswordHashResult scryptHash = scryptOnly.hash("hunter2".toCharArray());
    assertTrue(scryptHash.encodedHash().contains("$alg=scrypt$"));

    PasswordHashingService modern = BouncyCastleHashingServices.modern(fastModernPolicy());
    assertInstanceOf(CredentialVerificationResult.Verified.class,
        modern.verify("hunter2".toCharArray(), scryptHash.encodedHash()));
    RehashDecision.Required required = assertInstanceOf(
        RehashDecision.Required.class,
        modern.needsRehash(scryptHash.encodedHash()));
    assertEquals(RehashReason.ALGORITHM_DEPRECATED, required.reason());
  }

  @Test
  @DisplayName("Construction of the modern profile leaves the global JCA provider order unchanged")
  void globalProviderOrderUntouched() {
    Provider[] before = Security.getProviders();
    String[] beforeNames = Arrays.stream(before)
        .map(Provider::getName).toArray(String[]::new);

    PasswordHashingService service = BouncyCastleHashingServices.modern(
        fastModernPolicy());
    PasswordHashResult hashed = service.hash("hunter2".toCharArray());
    assertInstanceOf(CredentialVerificationResult.Verified.class,
        service.verify("hunter2".toCharArray(), hashed.encodedHash()));

    Provider[] after = Security.getProviders();
    String[] afterNames = Arrays.stream(after)
        .map(Provider::getName).toArray(String[]::new);
    assertArrayEquals(beforeNames, afterNames);
  }

  @Test
  @DisplayName("BouncyCastleHashingServices.modernPolicy uses the OWASP-2023 reference parameters")
  void referenceModernPolicy() {
    PasswordHashPolicy policy = BouncyCastleHashingServices.modernPolicy();
    assertEquals(Argon2idParameterNames.ALGORITHM, policy.preferredAlgorithm());
    assertEquals(Argon2idParameterNames.PROVIDER_ID, policy.preferredProviderId());
    assertEquals(Integer.toString(Argon2idDefaults.DEFAULT_MEMORY_KIB),
        policy.defaultParameters(Argon2idParameterNames.ALGORITHM)
            .get(Argon2idParameterNames.MEMORY_KIB));
    assertEquals(Integer.toString(ScryptDefaults.DEFAULT_N),
        policy.defaultParameters(ScryptParameterNames.ALGORITHM)
            .get(ScryptParameterNames.N));
    assertTrue(policy.acceptableAlgorithms().contains(BcryptParameterNames.ALGORITHM));
    assertTrue(policy.acceptableAlgorithms().contains(Pbkdf2ParameterNames.ALGORITHM));
  }

  @Test
  @DisplayName("ServiceLoader discovery sees all three BC providers from this module")
  void serviceLoaderDiscoversAllBcProviders() {
    PasswordHashProviderRegistry registry =
        PasswordHashProviderRegistry.fromServiceLoader();
    assertTrue(registry.knownProviderIds().contains(Argon2idParameterNames.PROVIDER_ID));
    assertTrue(registry.knownProviderIds().contains(BcryptParameterNames.PROVIDER_ID));
    assertTrue(registry.knownProviderIds().contains(ScryptParameterNames.PROVIDER_ID));
  }

  @Test
  @DisplayName("Modern profile requested without Argon2id provider fails fast on construction")
  void modernRequestedWithoutBouncyCastleFailsFast() {
    // PasswordHashingServices.defaults(...) builds an explicit registry
    // with only the PBKDF2 provider. Passing a modern-shaped policy
    // means the preferred provider is not registered -> fail fast.
    PasswordHashPolicy modernPolicy = fastModernPolicy();
    IllegalStateException ex = assertThrows(IllegalStateException.class,
        () -> PasswordHashingServices.defaults(modernPolicy));
    assertTrue(ex.getMessage().toLowerCase().contains("provider"));
  }

  // ── Helpers ───────────────────────────────────────────────────────

  private static PasswordHashPolicy coreOnlyPbkdf2Policy() {
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

  private static PasswordHashPolicy bcryptOnlyPolicy() {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(BcryptParameterNames.COST, "4");
    Map<String, String> min = new LinkedHashMap<>();
    min.put(BcryptParameterNames.COST, "4");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(BcryptParameterNames.COST, "6");
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(BcryptParameterNames.ALGORITHM)
        .preferredProviderId(BcryptParameterNames.PROVIDER_ID)
        .defaultParameters(BcryptParameterNames.ALGORITHM, defaults)
        .minimumParameters(BcryptParameterNames.ALGORITHM, min)
        .maximumParameters(BcryptParameterNames.ALGORITHM, max)
        .build();
  }

  private static PasswordHashPolicy scryptOnlyPolicy() {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(ScryptParameterNames.N, "1024");
    defaults.put(ScryptParameterNames.R, "8");
    defaults.put(ScryptParameterNames.P, "1");
    defaults.put(ScryptParameterNames.HASH_LENGTH, "32");
    Map<String, String> min = new LinkedHashMap<>();
    min.put(ScryptParameterNames.N, "512");
    min.put(ScryptParameterNames.R, "4");
    min.put(ScryptParameterNames.P, "1");
    min.put(ScryptParameterNames.HASH_LENGTH, "32");
    min.put(ScryptParameterNames.SALT_LENGTH, "16");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(ScryptParameterNames.N, "2048");
    max.put(ScryptParameterNames.R, "16");
    max.put(ScryptParameterNames.P, "4");
    max.put(ScryptParameterNames.HASH_LENGTH, "64");
    max.put(ScryptParameterNames.SALT_LENGTH, "64");
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(ScryptParameterNames.ALGORITHM)
        .preferredProviderId(ScryptParameterNames.PROVIDER_ID)
        .defaultParameters(ScryptParameterNames.ALGORITHM, defaults)
        .minimumParameters(ScryptParameterNames.ALGORITHM, min)
        .maximumParameters(ScryptParameterNames.ALGORITHM, max)
        .build();
  }
}
