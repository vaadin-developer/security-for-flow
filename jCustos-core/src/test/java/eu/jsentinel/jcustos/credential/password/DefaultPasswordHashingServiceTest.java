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
package eu.jsentinel.jcustos.credential.password;

import eu.jsentinel.jcustos.credential.CredentialType;
import eu.jsentinel.jcustos.credential.InternalAuditEventType;
import eu.jsentinel.jcustos.credential.PublicFailureType;
import eu.jsentinel.jcustos.credential.password.dummy.DefaultDummyVerificationService;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashCodec;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashEnvelope;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashFormatVersion;
import eu.jsentinel.jcustos.credential.password.limiter.NoLimitKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2Defaults;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterValidator;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2PasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.pepper.NoOpPepperService;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashValidator;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashParameterValidatorRegistry;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProviderRegistry;
import eu.jsentinel.jcustos.credential.password.rehash.RehashDecisionEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DefaultPasswordHashingServiceTest {

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

  private DefaultPasswordHashingService buildService(PasswordHashPolicy policy) {
    PasswordHashProviderRegistry registry = new PasswordHashProviderRegistry(
        List.of(new Pbkdf2PasswordHashProvider()));
    return new DefaultPasswordHashingService(
        PasswordHashCodec.DEFAULT,
        new DefaultPasswordHashValidator(
            new PasswordHashParameterValidatorRegistry(List.of(
                new Pbkdf2ParameterValidator()))),
        registry,
        NoOpPepperService.INSTANCE,
        policy,
        new RehashDecisionEngine(),
        NoLimitKdfExecutionLimiter.INSTANCE,
        new DefaultDummyVerificationService(registry, policy, PasswordHashCodec.DEFAULT));
  }

  @Test
  @DisplayName("hash then verify succeeds for the same password")
  void hashThenVerifyMatches() {
    DefaultPasswordHashingService service = buildService(fastTestPolicy());
    PasswordHashResult hashed = service.hash("hunter2".toCharArray());
    CredentialVerificationResult result = service.verify(
        "hunter2".toCharArray(), hashed.encodedHash());
    CredentialVerificationResult.Verified v = assertInstanceOf(
        CredentialVerificationResult.Verified.class, result);
    assertEquals(hashed.encodedHash(), v.originalEncodedHash(),
        "originalEncodedHash must round-trip the input so CAS rehash works");
    assertEquals(CredentialType.PASSWORD, v.credentialType());
    assertEquals(Pbkdf2ParameterNames.ALGORITHM, v.algorithm());
    assertEquals(Pbkdf2ParameterNames.PROVIDER_ID, v.providerId());
  }

  @Test
  @DisplayName("Wrong password yields generic INVALID_CREDENTIALS with MISMATCH internal")
  void wrongPasswordReturnsGenericFailure() {
    DefaultPasswordHashingService service = buildService(fastTestPolicy());
    PasswordHashResult hashed = service.hash("hunter2".toCharArray());
    CredentialVerificationResult result = service.verify(
        "hunter3".toCharArray(), hashed.encodedHash());
    CredentialVerificationResult.Failed f = assertInstanceOf(
        CredentialVerificationResult.Failed.class, result);
    assertEquals(PublicFailureType.INVALID_CREDENTIALS, f.publicFailureType());
    assertEquals(InternalAuditEventType.VERIFICATION_FAILED_MISMATCH,
        f.internalAuditEventType());
  }

  @Test
  @DisplayName("Malformed envelope is rejected as DECODE_ERROR but public reason stays generic")
  void malformedEnvelopeMapsToDecodeError() {
    DefaultPasswordHashingService service = buildService(fastTestPolicy());
    CredentialVerificationResult result = service.verify(
        "x".toCharArray(), "not-an-envelope");
    CredentialVerificationResult.Failed f = assertInstanceOf(
        CredentialVerificationResult.Failed.class, result);
    assertEquals(PublicFailureType.INVALID_CREDENTIALS, f.publicFailureType());
    assertEquals(InternalAuditEventType.VERIFICATION_FAILED_DECODE_ERROR,
        f.internalAuditEventType());
  }

  @Test
  @DisplayName("Null encodedHash maps to DECODE_ERROR with generic public failure")
  void nullEncodedHashIsHandled() {
    DefaultPasswordHashingService service = buildService(fastTestPolicy());
    CredentialVerificationResult result = service.verify(
        "x".toCharArray(), null);
    CredentialVerificationResult.Failed f = assertInstanceOf(
        CredentialVerificationResult.Failed.class, result);
    assertEquals(InternalAuditEventType.VERIFICATION_FAILED_DECODE_ERROR,
        f.internalAuditEventType());
  }

  @Test
  @DisplayName("Envelope referencing an unregistered provider maps to UNKNOWN_PROVIDER")
  void unknownProviderMapsToInternalUnknownProvider() {
    PasswordHashPolicy policy = fastTestPolicy();
    DefaultPasswordHashingService service = buildService(policy);

    Map<String, String> params = new LinkedHashMap<>();
    params.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    params.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    params.put(Pbkdf2ParameterNames.SALT, "AAAAAAAAAAAAAAAAAAAAAA==");
    PasswordHashEnvelope env = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1,
        CredentialType.PASSWORD,
        Pbkdf2ParameterNames.ALGORITHM,
        "ghost-provider",
        1,
        Optional.empty(),
        params,
        "ZGVyaXZlZA=="
    );
    String encoded = PasswordHashCodec.DEFAULT.encode(env);

    CredentialVerificationResult.Failed f = assertInstanceOf(
        CredentialVerificationResult.Failed.class,
        service.verify("x".toCharArray(), encoded));
    assertEquals(PublicFailureType.INVALID_CREDENTIALS, f.publicFailureType());
    assertEquals(InternalAuditEventType.VERIFICATION_FAILED_UNKNOWN_PROVIDER,
        f.internalAuditEventType());
  }

  @Test
  @DisplayName("Envelope with unsupported algorithm is rejected by the validator stage")
  void unsupportedAlgorithmMapsToInvalidParameters() {
    PasswordHashPolicy policy = fastTestPolicy();
    DefaultPasswordHashingService service = buildService(policy);

    Map<String, String> params = new LinkedHashMap<>();
    params.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    params.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    params.put(Pbkdf2ParameterNames.SALT, "AAAAAAAAAAAAAAAAAAAAAA==");
    PasswordHashEnvelope env = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1,
        CredentialType.PASSWORD,
        "Argon2id",
        "argon2-bc",
        1,
        Optional.empty(),
        params,
        "ZGVyaXZlZA=="
    );
    String encoded = PasswordHashCodec.DEFAULT.encode(env);

    CredentialVerificationResult.Failed f = assertInstanceOf(
        CredentialVerificationResult.Failed.class,
        service.verify("x".toCharArray(), encoded));
    assertEquals(InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
        f.internalAuditEventType());
  }

  @Test
  @DisplayName("Envelope referencing a pepper key under NoOpPepperService maps to UNKNOWN_PEPPER_KEY")
  void peppperKeyButNoPepperServiceMapsToUnknownPepper() {
    PasswordHashPolicy policy = fastTestPolicy();
    DefaultPasswordHashingService service = buildService(policy);

    Map<String, String> params = new LinkedHashMap<>();
    params.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    params.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    params.put(Pbkdf2ParameterNames.SALT, "AAAAAAAAAAAAAAAAAAAAAA==");
    PasswordHashEnvelope env = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1,
        CredentialType.PASSWORD,
        Pbkdf2ParameterNames.ALGORITHM,
        Pbkdf2ParameterNames.PROVIDER_ID,
        1,
        Optional.of("pepper-2026-04"),
        params,
        "ZGVyaXZlZA=="
    );
    String encoded = PasswordHashCodec.DEFAULT.encode(env);

    CredentialVerificationResult.Failed f = assertInstanceOf(
        CredentialVerificationResult.Failed.class,
        service.verify("x".toCharArray(), encoded));
    assertEquals(InternalAuditEventType.VERIFICATION_FAILED_UNKNOWN_PEPPER_KEY,
        f.internalAuditEventType());
  }

  @Test
  @DisplayName("Policy-version drift: stored envelope older than active policy triggers rehash")
  void policyVersionDriftTriggersRehash() {
    PasswordHashPolicy oldPolicy = fastTestPolicy();
    DefaultPasswordHashingService oldService = buildService(oldPolicy);
    String oldHash = oldService.hash("hunter2".toCharArray()).encodedHash();

    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    defaults.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    Map<String, String> min = new LinkedHashMap<>(defaults);
    min.put(Pbkdf2ParameterNames.SALT_LENGTH, "16");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(Pbkdf2ParameterNames.ITERATIONS, "2000");
    max.put(Pbkdf2ParameterNames.KEY_LENGTH, "64");
    max.put(Pbkdf2ParameterNames.SALT_LENGTH, "64");
    PasswordHashPolicy newPolicy = DefaultPasswordHashPolicy.builder()
        .policyVersion(2)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, defaults)
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, min)
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, max)
        .build();
    DefaultPasswordHashingService newService = buildService(newPolicy);

    RehashDecision decision = newService.needsRehash(oldHash);
    assertInstanceOf(RehashDecision.Required.class, decision);
    assertEquals(RehashReason.POLICY_VERSION_OUTDATED,
        ((RehashDecision.Required) decision).reason());
  }

  @Test
  @DisplayName("needsRehash on a perfectly aligned envelope returns NotRequired")
  void needsRehashNotRequiredWhenAligned() {
    DefaultPasswordHashingService service = buildService(fastTestPolicy());
    String hash = service.hash("hunter2".toCharArray()).encodedHash();
    assertSame(RehashDecision.NotRequired.INSTANCE, service.needsRehash(hash));
  }

  @Test
  @DisplayName("needsRehash on malformed input is a no-op")
  void needsRehashMalformedIsNoop() {
    DefaultPasswordHashingService service = buildService(fastTestPolicy());
    assertSame(RehashDecision.NotRequired.INSTANCE,
        service.needsRehash("not-an-envelope"));
    assertSame(RehashDecision.NotRequired.INSTANCE,
        service.needsRehash(null));
  }

  @Test
  @DisplayName("Construction fails fast when the preferred provider is not registered")
  void preferredProviderMustBeRegistered() {
    PasswordHashPolicy policy = fastTestPolicy();
    PasswordHashProviderRegistry emptyRegistry =
        new PasswordHashProviderRegistry(java.util.List.of());
    PasswordHashProviderRegistry validRegistry =
        new PasswordHashProviderRegistry(List.of(new Pbkdf2PasswordHashProvider()));
    assertThrows(IllegalStateException.class, () ->
        new DefaultPasswordHashingService(
            PasswordHashCodec.DEFAULT,
            new DefaultPasswordHashValidator(
                new PasswordHashParameterValidatorRegistry(List.of(
                    new Pbkdf2ParameterValidator()))),
            emptyRegistry,
            NoOpPepperService.INSTANCE,
            policy,
            new RehashDecisionEngine(),
            NoLimitKdfExecutionLimiter.INSTANCE,
            new DefaultDummyVerificationService(validRegistry, policy, PasswordHashCodec.DEFAULT)));
  }

  @Test
  @DisplayName("Failed public reason is always INVALID_CREDENTIALS for every failure path")
  void everyFailurePathMapsToGenericPublicReason() {
    DefaultPasswordHashingService service = buildService(fastTestPolicy());
    // mismatch
    String hash = service.hash("a".toCharArray()).encodedHash();
    assertEquals(PublicFailureType.INVALID_CREDENTIALS,
        ((CredentialVerificationResult.Failed)
            service.verify("b".toCharArray(), hash)).publicFailureType());
    // decode
    assertEquals(PublicFailureType.INVALID_CREDENTIALS,
        ((CredentialVerificationResult.Failed)
            service.verify("a".toCharArray(), "not-an-envelope")).publicFailureType());
    // null
    assertEquals(PublicFailureType.INVALID_CREDENTIALS,
        ((CredentialVerificationResult.Failed)
            service.verify("a".toCharArray(), null)).publicFailureType());
  }

  @Test
  @DisplayName("Phase-1a NoOpPepperService never resolves a key and never publishes one")
  void noOpPepperServiceContract() {
    assertEquals(Optional.empty(), NoOpPepperService.INSTANCE.activeKeyId());
    assertEquals(Optional.empty(), NoOpPepperService.INSTANCE.resolve("anything"));
    assertSame(NoOpPepperService.INSTANCE, NoOpPepperService.INSTANCE);
  }
}
