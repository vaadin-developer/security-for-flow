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
package com.svenruppert.vaadin.security.credential.password;

import com.svenruppert.vaadin.security.credential.InternalAuditEventType;
import com.svenruppert.vaadin.security.credential.password.envelope.PasswordHashCodec;
import com.svenruppert.vaadin.security.credential.password.limiter.NoLimitKdfExecutionLimiter;
import com.svenruppert.vaadin.security.credential.password.pbkdf2.Pbkdf2ParameterNames;
import com.svenruppert.vaadin.security.credential.password.pepper.InMemoryPepperService;
import com.svenruppert.vaadin.security.credential.password.policy.DefaultPasswordHashPolicy;
import com.svenruppert.vaadin.security.credential.password.policy.PasswordHashPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;

class PepperRotationTest {

  private static byte[] key32(byte fill) {
    byte[] b = new byte[32];
    Arrays.fill(b, fill);
    return b;
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

  @Test
  @DisplayName("Verify with the current pepper key needs no rehash")
  void currentKeyNoRehash() {
    InMemoryPepperService pepper = InMemoryPepperService.withActiveKey(
        "k2", key32((byte) 0x22));
    PasswordHashingService service = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE, pepper);
    PasswordHashResult hashed = service.hash("hunter2".toCharArray());
    assertInstanceOf(CredentialVerificationResult.Verified.class,
        service.verify("hunter2".toCharArray(), hashed.encodedHash()));
    assertSame(RehashDecision.NotRequired.INSTANCE,
        service.needsRehash(hashed.encodedHash()));
  }

  @Test
  @DisplayName("Old accepted key still verifies but triggers PEPPER_KEY_ROTATED rehash")
  void oldAcceptedKeyTriggersRehash() {
    // Service 1: only the old key is active when the envelope was created.
    InMemoryPepperService oldOnly = InMemoryPepperService.withActiveKey(
        "k1", key32((byte) 0x11));
    PasswordHashingService oldService = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE, oldOnly);
    PasswordHashResult historicalHash = oldService.hash("hunter2".toCharArray());
    assertEquals("k1",
        PasswordHashCodec.DEFAULT.decode(historicalHash.encodedHash())
            .envelope().pepperKeyId().orElseThrow());

    // Service 2: rotation window — both keys present, k2 is now active.
    InMemoryPepperService rotating = InMemoryPepperService.builder()
        .addKey("k1", key32((byte) 0x11))
        .addKey("k2", key32((byte) 0x22))
        .activeKeyId("k2")
        .build();
    PasswordHashingService rotatingService = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE, rotating);

    // Envelope still verifies under the rotation service because k1 is accepted.
    assertInstanceOf(CredentialVerificationResult.Verified.class,
        rotatingService.verify("hunter2".toCharArray(),
            historicalHash.encodedHash()));

    // …and the rehash engine flags the envelope for migration to k2.
    RehashDecision.Required required = assertInstanceOf(
        RehashDecision.Required.class,
        rotatingService.needsRehash(historicalHash.encodedHash()));
    assertEquals(RehashReason.PEPPER_KEY_ROTATED, required.reason());
  }

  @Test
  @DisplayName("Retired key (not in service) verifies as UNKNOWN_PEPPER_KEY (CWE-693)")
  void retiredKeyIsRejected() {
    InMemoryPepperService oldOnly = InMemoryPepperService.withActiveKey(
        "k1", key32((byte) 0x11));
    PasswordHashingService oldService = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE, oldOnly);
    PasswordHashResult historicalHash = oldService.hash("hunter2".toCharArray());

    // After full retirement of k1, only k2 is known.
    InMemoryPepperService afterRetirement = InMemoryPepperService.withActiveKey(
        "k2", key32((byte) 0x22));
    PasswordHashingService cutover = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE,
        afterRetirement);

    CredentialVerificationResult.Failed failed = assertInstanceOf(
        CredentialVerificationResult.Failed.class,
        cutover.verify("hunter2".toCharArray(), historicalHash.encodedHash()));
    assertEquals(InternalAuditEventType.VERIFICATION_FAILED_UNKNOWN_PEPPER_KEY,
        failed.internalAuditEventType());
  }

  @Test
  @DisplayName("Transition from no pepper to pepper triggers PEPPER_KEY_ROTATED rehash")
  void noPepperToPepperTriggersRehash() {
    // Stored under NoOp pepper (envelope has no pepperKeyId).
    PasswordHashingService noPepper = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE);
    PasswordHashResult historicalHash = noPepper.hash("hunter2".toCharArray());

    // Then the operator introduces a real pepper service.
    InMemoryPepperService rotated = InMemoryPepperService.withActiveKey(
        "pepper-2026-04", key32((byte) 0x33));
    PasswordHashingService withPepper = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE, rotated);

    // The old non-peppered envelope still verifies (the provider runs
    // KDF without HMAC because the envelope has no pepperKeyId), …
    assertInstanceOf(CredentialVerificationResult.Verified.class,
        withPepper.verify("hunter2".toCharArray(), historicalHash.encodedHash()));
    // …and the rehash engine asks for a transition.
    RehashDecision.Required required = assertInstanceOf(
        RehashDecision.Required.class,
        withPepper.needsRehash(historicalHash.encodedHash()));
    assertEquals(RehashReason.PEPPER_KEY_ROTATED, required.reason());
  }

  @Test
  @DisplayName("Rolling back from pepper to NoOp also triggers PEPPER_KEY_ROTATED")
  void pepperToNoPepperTriggersRehash() {
    InMemoryPepperService pepper = InMemoryPepperService.withActiveKey(
        "k1", key32((byte) 0x11));
    PasswordHashingService withPepper = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE, pepper);
    PasswordHashResult pepperedHash = withPepper.hash("hunter2".toCharArray());

    // The operator decides to remove pepper entirely.
    PasswordHashingService noPepper = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE);

    // Verification fails because the verifier no longer holds k1.
    assertInstanceOf(CredentialVerificationResult.Failed.class,
        noPepper.verify("hunter2".toCharArray(), pepperedHash.encodedHash()));
  }
}
