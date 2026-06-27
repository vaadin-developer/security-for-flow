package com.svenruppert.jsentinel.jwt.api;

import java.util.Set;

/**
 * Named, curated {@link AlgorithmAllowList}s. The V00.76 default is
 * {@link #STRICT_MODERN}; broader or FIPS sets are explicit opt-ins.
 *
 * @since 00.76.00
 */
public enum AlgorithmProfile {

  /** RS256, PS256, ES256, EdDSA — covers ~90% of OIDC IDPs. */
  STRICT_MODERN,

  /** STRICT_MODERN plus the 384/512 RSA/EC/PS variants, for legacy estates. */
  LEGACY_BROAD,

  /** FIPS 140-3-approved set: RS/ES 256/384/512 — no EdDSA, no PS in V00.76. */
  FIPS_140_3,

  /** Sentinel for "an explicit {@link AlgorithmAllowList} is supplied instead". */
  CUSTOM;

  /**
   * @return the allow-list for this profile
   * @throws UnsupportedOperationException for {@link #CUSTOM}, which has no
   *         intrinsic set — the caller must provide an explicit allow-list
   */
  public AlgorithmAllowList toAllowList() {
    return switch (this) {
      case STRICT_MODERN -> new AlgorithmAllowList(Set.of(
          JwsAlgorithm.RS256, JwsAlgorithm.PS256, JwsAlgorithm.ES256, JwsAlgorithm.EdDSA));
      case LEGACY_BROAD -> new AlgorithmAllowList(Set.of(
          JwsAlgorithm.RS256, JwsAlgorithm.PS256, JwsAlgorithm.ES256, JwsAlgorithm.EdDSA,
          JwsAlgorithm.RS384, JwsAlgorithm.RS512, JwsAlgorithm.ES384, JwsAlgorithm.ES512,
          JwsAlgorithm.PS384, JwsAlgorithm.PS512));
      case FIPS_140_3 -> new AlgorithmAllowList(Set.of(
          JwsAlgorithm.RS256, JwsAlgorithm.RS384, JwsAlgorithm.RS512,
          JwsAlgorithm.ES256, JwsAlgorithm.ES384, JwsAlgorithm.ES512));
      case CUSTOM -> throw new UnsupportedOperationException(
          "CUSTOM has no intrinsic allow-list; supply an explicit AlgorithmAllowList");
    };
  }
}
