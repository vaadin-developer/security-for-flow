package eu.jsentinel.jcustos.events.keys;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.signature.Ed25519SignatureAlgorithm;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

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

  @Test
  @DisplayName("R00: signingSnapshot reflects the current key and signs verifiably under its own id")
  void signingSnapshotIsSelfConsistent() {
    InMemoryKeyManagement km = new InMemoryKeyManagement(algorithm, K1);
    km.rotate(K2);
    SigningKeySnapshot snapshot = km.signingSnapshot();
    assertEquals(K2, snapshot.keyId());
    byte[] data = "base".getBytes(StandardCharsets.UTF_8);
    byte[] signature = snapshot.algorithm().sign(data, snapshot.privateKey());
    assertTrue(snapshot.algorithm().verify(data, signature,
        km.resolveVerificationKey(snapshot.keyId()).orElseThrow()));
  }

  @Test
  @DisplayName("R00: signingSnapshot stays self-consistent while rotate() runs concurrently")
  void snapshotSelfConsistentUnderConcurrentRotation() throws InterruptedException {
    // No mock, no fake interleave: a real rotation loop hammers the manager
    // while snapshots are taken. Every snapshot must sign verifiably under its
    // OWN keyId — with the old two-volatile-store layout a reader could
    // observe the new id paired with the old private key, and this invariant
    // would fail.
    InMemoryKeyManagement km = new InMemoryKeyManagement(algorithm, K1);
    byte[] data = "base".getBytes(StandardCharsets.UTF_8);
    AtomicBoolean stop = new AtomicBoolean();
    AtomicInteger rotations = new AtomicInteger();
    Thread rotator = new Thread(() -> {
      while (!stop.get()) {
        km.rotate(KeyId.of("rotated-" + rotations.incrementAndGet()));
      }
    });
    rotator.start();
    try {
      for (int i = 0; i < 100; i++) {
        SigningKeySnapshot snapshot = km.signingSnapshot();
        byte[] signature = snapshot.algorithm().sign(data, snapshot.privateKey());
        PublicKey verificationKey =
            km.resolveVerificationKey(snapshot.keyId()).orElseThrow();
        assertTrue(snapshot.algorithm().verify(data, signature, verificationKey),
            "snapshot keyId and private key must always belong together");
      }
    } finally {
      stop.set(true);
      rotator.join();
    }
  }
}
