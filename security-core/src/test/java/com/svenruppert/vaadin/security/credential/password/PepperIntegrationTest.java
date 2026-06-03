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
import com.svenruppert.vaadin.security.credential.PublicFailureType;
import com.svenruppert.vaadin.security.credential.password.envelope.PasswordHashCodec;
import com.svenruppert.vaadin.security.credential.password.envelope.PasswordHashEnvelope;
import com.svenruppert.vaadin.security.credential.password.limiter.NoLimitKdfExecutionLimiter;
import com.svenruppert.vaadin.security.credential.password.pbkdf2.Pbkdf2ParameterNames;
import com.svenruppert.vaadin.security.credential.password.pepper.InMemoryPepperService;
import com.svenruppert.vaadin.security.credential.password.pepper.PepperApplicator;
import com.svenruppert.vaadin.security.credential.password.policy.DefaultPasswordHashPolicy;
import com.svenruppert.vaadin.security.credential.password.policy.PasswordHashPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PepperIntegrationTest {

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
  @DisplayName("hash + verify roundtrip works with an active pepper key")
  void roundtripWithPepper() {
    InMemoryPepperService pepper = InMemoryPepperService.withActiveKey(
        "pepper-2026-04", key32((byte) 0x11));
    PasswordHashingService service = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE, pepper);

    PasswordHashResult hashed = service.hash("hunter2".toCharArray());
    assertTrue(hashed.encodedHash().contains("$pep=pepper-2026-04$"),
        "envelope must record the active pepper key id");

    assertInstanceOf(CredentialVerificationResult.Verified.class,
        service.verify("hunter2".toCharArray(), hashed.encodedHash()));
  }

  @Test
  @DisplayName("Wrong password with pepper yields generic INVALID_CREDENTIALS / MISMATCH")
  void wrongPasswordWithPepper() {
    InMemoryPepperService pepper = InMemoryPepperService.withActiveKey(
        "pepper-2026-04", key32((byte) 0x11));
    PasswordHashingService service = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE, pepper);
    PasswordHashResult hashed = service.hash("hunter2".toCharArray());

    CredentialVerificationResult.Failed failed = assertInstanceOf(
        CredentialVerificationResult.Failed.class,
        service.verify("hunter3".toCharArray(), hashed.encodedHash()));
    assertEquals(PublicFailureType.INVALID_CREDENTIALS, failed.publicFailureType());
    assertEquals(InternalAuditEventType.VERIFICATION_FAILED_MISMATCH,
        failed.internalAuditEventType());
  }

  @Test
  @DisplayName("Stored envelope with a pepper key id under NoOp pepper still maps to UNKNOWN_PEPPER_KEY")
  void noOpPepperRejectsPepperedEnvelope() {
    // Build a peppered envelope under one service ...
    InMemoryPepperService pepper = InMemoryPepperService.withActiveKey(
        "pepper-2026-04", key32((byte) 0x11));
    PasswordHashingService withPepper = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE, pepper);
    PasswordHashResult peppered = withPepper.hash("hunter2".toCharArray());

    // ... then try to verify it under the NoOp pepper service.
    PasswordHashingService noPepper = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE);
    CredentialVerificationResult.Failed failed = assertInstanceOf(
        CredentialVerificationResult.Failed.class,
        noPepper.verify("hunter2".toCharArray(), peppered.encodedHash()));
    assertEquals(PublicFailureType.INVALID_CREDENTIALS, failed.publicFailureType());
    assertEquals(InternalAuditEventType.VERIFICATION_FAILED_UNKNOWN_PEPPER_KEY,
        failed.internalAuditEventType());
  }

  @Test
  @DisplayName("Pepper changes the inner hash: peppered and non-peppered envelopes for the same password differ")
  void pepperedHashDiffersFromUnpeppered() {
    InMemoryPepperService pepper = InMemoryPepperService.withActiveKey(
        "pepper-2026-04", key32((byte) 0x11));
    PasswordHashingService withPepper = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE, pepper);
    PasswordHashingService noPepper = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE);

    // Same SecureRandom across both? No — they each draw fresh salts.
    // What we can assert: peppered envelope carries a pepper key id, the
    // plain one does not, and the encoded strings differ.
    PasswordHashResult a = withPepper.hash("k".toCharArray());
    PasswordHashResult b = noPepper.hash("k".toCharArray());
    assertNotEquals(a.encodedHash(), b.encodedHash());
    PasswordHashEnvelope envA = PasswordHashCodec.DEFAULT
        .decode(a.encodedHash()).envelope();
    PasswordHashEnvelope envB = PasswordHashCodec.DEFAULT
        .decode(b.encodedHash()).envelope();
    assertTrue(envA.pepperKeyId().isPresent());
    assertTrue(envB.pepperKeyId().isEmpty());
  }

  @Test
  @DisplayName("PepperApplicator(no pepper) returns the KDF output verbatim (clone)")
  void applicatorNoPepperIdentity() {
    byte[] kdf = new byte[] {1, 2, 3, 4};
    byte[] out = PepperApplicator.apply(kdf,
        java.util.Optional.empty());
    org.junit.jupiter.api.Assertions.assertArrayEquals(kdf, out);
    org.junit.jupiter.api.Assertions.assertNotSame(kdf, out);
  }
}
