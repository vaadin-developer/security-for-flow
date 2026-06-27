package com.svenruppert.jsentinel.jwt.api;

import java.security.PublicKey;
import java.util.Optional;

/**
 * Resolves signing keys from a JWKS source. Implementations cache with a TTL,
 * refresh once on a {@code kid} miss (single-flight), and negative-cache
 * endpoint failures so a transient outage cannot turn into a DoS against the IDP.
 *
 * <p>V00.76 is asymmetric-only, so keys are {@link PublicKey}s.
 *
 * @since 00.76.00
 */
public interface JwksClient {

  /**
   * Resolves the public key for a header {@code kid} / {@code alg}. A miss may
   * trigger a single synchronous refresh before giving up.
   *
   * @param kid the (untrusted) header key id
   * @param alg the (allow-listed) algorithm
   * @return the matching public key, or empty if none is known
   */
  Optional<PublicKey> findKey(String kid, JwsAlgorithm alg);

  /**
   * Forces a single refresh from the JWKS source (operator override).
   *
   * @return the outcome of the refresh
   */
  JwksRefreshResult refreshOnce();
}
