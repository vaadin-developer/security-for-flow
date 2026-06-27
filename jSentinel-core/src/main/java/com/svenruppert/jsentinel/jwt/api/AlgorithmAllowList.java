package com.svenruppert.jsentinel.jwt.api;

import java.util.Objects;
import java.util.Set;

/**
 * The explicit set of {@link JwsAlgorithm}s a validator will accept. An empty
 * allow-list accepts nothing — there is no implicit "allow all". This is the
 * mandatory gate that closes the algorithm-confusion / downgrade CVE class.
 *
 * @param allowed the permitted algorithms (defensively copied, immutable)
 * @since 00.76.00
 */
public record AlgorithmAllowList(Set<JwsAlgorithm> allowed) {

  public AlgorithmAllowList {
    allowed = Set.copyOf(Objects.requireNonNull(allowed, "allowed"));
  }

  /**
   * @param headerAlg the raw, untrusted JOSE-header {@code alg} value
   * @return {@code true} only if it maps to a known algorithm that is in the list
   */
  public boolean allows(String headerAlg) {
    return JwsAlgorithm.fromHeader(headerAlg).map(allowed::contains).orElse(false);
  }

  /**
   * @param algorithm a resolved algorithm
   * @return {@code true} if it is in the list
   */
  public boolean allows(JwsAlgorithm algorithm) {
    return allowed.contains(algorithm);
  }
}
