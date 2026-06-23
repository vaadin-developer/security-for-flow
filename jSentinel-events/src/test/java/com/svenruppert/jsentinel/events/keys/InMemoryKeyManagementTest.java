package com.svenruppert.jsentinel.events.keys;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
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

import com.svenruppert.jsentinel.events.api.KeyId;
import com.svenruppert.jsentinel.events.signature.Ed25519SignatureAlgorithm;
import com.svenruppert.jsentinel.events.signature.SignatureAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryKeyManagement")
class InMemoryKeyManagementTest {

  private final SignatureAlgorithm algorithm = new Ed25519SignatureAlgorithm();
  private static final KeyId K1 = KeyId.of("key-1");
  private static final KeyId K2 = KeyId.of("key-2");

  @Test
  @DisplayName("the initial key is ACTIVE and signs verifiably")
  void initialKeyActiveAndUsable() {
    InMemoryKeyManagement km = new InMemoryKeyManagement(algorithm, K1);
    assertEquals(K1, km.currentKeyId());
    assertEquals(KeyStatus.ACTIVE, km.keyStatus(K1));
    assertTrue(km.resolveVerificationKey(K1).isPresent());

    byte[] data = "base".getBytes(StandardCharsets.UTF_8);
    byte[] sig = km.currentAlgorithm().sign(data, km.currentSigningKey());
    assertTrue(km.currentAlgorithm().verify(data, sig, km.resolveVerificationKey(K1).orElseThrow()));
  }

  @Test
  @DisplayName("rotation makes the old key ACCEPTED_FOR_VERIFICATION and the new key ACTIVE")
  void rotationKeepsOldKeyVerifiable() {
    InMemoryKeyManagement km = new InMemoryKeyManagement(algorithm, K1);
    km.rotate(K2);
    assertEquals(K2, km.currentKeyId());
    assertEquals(KeyStatus.ACTIVE, km.keyStatus(K2));
    assertEquals(KeyStatus.ACCEPTED_FOR_VERIFICATION, km.keyStatus(K1));
    assertTrue(km.resolveVerificationKey(K1).isPresent());
    assertTrue(km.resolveVerificationKey(K2).isPresent());
  }

  @Test
  @DisplayName("a revoked key reports REVOKED")
  void revokedKeyReportsRevoked() {
    InMemoryKeyManagement km = new InMemoryKeyManagement(algorithm, K1);
    km.revoke(K1);
    assertEquals(KeyStatus.REVOKED, km.keyStatus(K1));
  }

  @Test
  @DisplayName("an unknown key is UNKNOWN and resolves to empty")
  void unknownKey() {
    InMemoryKeyManagement km = new InMemoryKeyManagement(algorithm, K1);
    assertEquals(KeyStatus.UNKNOWN, km.keyStatus(KeyId.of("nope")));
    assertTrue(km.resolveVerificationKey(KeyId.of("nope")).isEmpty());
  }
}
