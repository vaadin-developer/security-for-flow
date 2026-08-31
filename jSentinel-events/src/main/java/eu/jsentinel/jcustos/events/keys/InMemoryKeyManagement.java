package eu.jsentinel.jcustos.events.keys;

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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithm;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link JSentinelEventSigningKeyProvider} +
 * {@link JSentinelEventVerificationKeyResolver} (Konzept §98). The default
 * key-management implementation for local setups and tests: it generates the
 * current key pair with the configured {@link SignatureAlgorithm} and supports
 * rotation and revocation without an API break.
 *
 * <p>Rotated-out keys stay {@link KeyStatus#ACCEPTED_FOR_VERIFICATION} so
 * in-flight envelopes still verify during the grace window.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class InMemoryKeyManagement
    implements JSentinelEventSigningKeyProvider, JSentinelEventVerificationKeyResolver {

  // R00: id and key pair live in ONE immutable holder behind a single volatile
  // reference, so a reader can never observe the new id paired with the old key
  // material (or vice versa) — the previous two separate volatile stores made
  // exactly that interleaving possible during rotate().
  private record CurrentKey(KeyId keyId, KeyPair keyPair) {
  }

  private final SignatureAlgorithm algorithm;
  private final Map<KeyId, PublicKey> verificationKeys = new ConcurrentHashMap<>();
  private final Set<KeyId> revoked = ConcurrentHashMap.newKeySet();

  private volatile CurrentKey current;

  /**
   * Creates a manager with a freshly generated initial key pair.
   *
   * @param algorithm the signature algorithm
   * @param initialKeyId the id of the initial signing key
   */
  public InMemoryKeyManagement(SignatureAlgorithm algorithm, KeyId initialKeyId) {
    this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
    Objects.requireNonNull(initialKeyId, "initialKeyId");
    KeyPair pair = algorithm.generateKeyPair();
    verificationKeys.put(initialKeyId, pair.getPublic());
    this.current = new CurrentKey(initialKeyId, pair);
  }

  @Override
  public KeyId currentKeyId() {
    return current.keyId();
  }

  @Override
  public PrivateKey currentSigningKey() {
    return current.keyPair().getPrivate();
  }

  @Override
  public SignatureAlgorithm currentAlgorithm() {
    return algorithm;
  }

  @Override
  public SigningKeySnapshot signingSnapshot() {
    // One volatile read — keyId and private key are guaranteed to belong to
    // the same key generation even while rotate() runs concurrently (R00).
    CurrentKey snapshot = current;
    return new SigningKeySnapshot(snapshot.keyId(), algorithm, snapshot.keyPair().getPrivate());
  }

  @Override
  public Optional<PublicKey> resolveVerificationKey(KeyId keyId) {
    return Optional.ofNullable(verificationKeys.get(Objects.requireNonNull(keyId, "keyId")));
  }

  @Override
  public KeyStatus keyStatus(KeyId keyId) {
    Objects.requireNonNull(keyId, "keyId");
    if (revoked.contains(keyId)) {
      return KeyStatus.REVOKED;
    }
    if (!verificationKeys.containsKey(keyId)) {
      return KeyStatus.UNKNOWN;
    }
    return keyId.equals(current.keyId())
        ? KeyStatus.ACTIVE
        : KeyStatus.ACCEPTED_FOR_VERIFICATION;
  }

  /**
   * Rotates to a freshly generated key. The previous key stays valid for
   * verification.
   *
   * @param newKeyId the id of the new signing key
   */
  public synchronized void rotate(KeyId newKeyId) {
    Objects.requireNonNull(newKeyId, "newKeyId");
    KeyPair pair = algorithm.generateKeyPair();
    // Publish the verification key BEFORE swapping the holder, so any reader
    // that already sees the new current key can also resolve it (R00). The
    // holder itself is swapped in a single volatile store.
    verificationKeys.put(newKeyId, pair.getPublic());
    this.current = new CurrentKey(newKeyId, pair);
  }

  /**
   * Revokes a key; subsequent {@link #keyStatus(KeyId)} reports
   * {@link KeyStatus#REVOKED}.
   *
   * @param keyId the key to revoke
   */
  public void revoke(KeyId keyId) {
    revoked.add(Objects.requireNonNull(keyId, "keyId"));
  }
}
