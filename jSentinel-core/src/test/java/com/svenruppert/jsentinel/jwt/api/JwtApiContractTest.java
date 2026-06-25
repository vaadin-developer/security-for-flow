package com.svenruppert.jsentinel.jwt.api;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("jwt/api value-type contracts")
class JwtApiContractTest {

  private static ValidatedJwt validated(Map<String, Object> claims) {
    return new ValidatedJwt("aaa.bbb.ccc",
        new JoseHeader("RS256", Optional.of("k1"), Optional.of("JWT")),
        claims, Instant.EPOCH);
  }

  @Test
  @DisplayName("ValidatedJwt exposes typed claims and masks the compact form")
  void claimAccessorsAndMasking() {
    ValidatedJwt v = validated(Map.of(
        "iss", "https://idp.example/", "sub", "alice", "exp", 1000L,
        "aud", List.of("api.example")));
    assertEquals(Optional.of("https://idp.example/"), v.issuer());
    assertEquals(Optional.of("alice"), v.subject());
    assertEquals(Optional.of(Instant.ofEpochSecond(1000)), v.expiresAt());
    assertEquals(Optional.of(List.of("api.example")), v.audience());
    assertFalse(v.toString().contains("aaa.bbb.ccc"), "raw compact must not leak");
    assertTrue(v.toString().contains("compact=***"));
  }

  @Test
  @DisplayName("audience() tolerates both the String and array shapes")
  void audienceTolerance() {
    assertEquals(Optional.of(List.of("single")),
        validated(Map.of("aud", "single")).audience());
    assertEquals(Optional.of(List.of("a", "b")),
        validated(Map.of("aud", List.of("a", "b"))).audience());
    assertEquals(Optional.empty(), validated(Map.of()).audience());
  }

  @Test
  @DisplayName("algorithm profiles resolve to the documented sets; CUSTOM has none")
  void algorithmProfiles() {
    AlgorithmAllowList strict = AlgorithmProfile.STRICT_MODERN.toAllowList();
    assertTrue(strict.allows(JwsAlgorithm.RS256));
    assertTrue(strict.allows(JwsAlgorithm.EdDSA));
    assertFalse(strict.allows(JwsAlgorithm.RS512));

    AlgorithmAllowList fips = AlgorithmProfile.FIPS_140_3.toAllowList();
    assertTrue(fips.allows(JwsAlgorithm.RS512));
    assertFalse(fips.allows(JwsAlgorithm.EdDSA), "FIPS set excludes EdDSA in V00.76");
    assertFalse(fips.allows(JwsAlgorithm.PS256), "FIPS set excludes PS in V00.76");

    assertThrows(UnsupportedOperationException.class,
        AlgorithmProfile.CUSTOM::toAllowList);
  }

  @Test
  @DisplayName("allow-list rejects alg:none and unknown / non-listed algorithms")
  void allowListRejectsNoneAndUnknown() {
    AlgorithmAllowList list = AlgorithmProfile.STRICT_MODERN.toAllowList();
    assertFalse(list.allows("none"), "alg:none can never be allowed");
    assertFalse(list.allows("HS256"), "HMAC is not allow-listed in V00.76");
    assertFalse(list.allows("bogus"));
    assertTrue(list.allows("RS256"));
  }

  @Test
  @DisplayName("JwsAlgorithm.fromHeader is null-safe and rejects unknown values")
  void fromHeader() {
    assertEquals(Optional.of(JwsAlgorithm.ES256), JwsAlgorithm.fromHeader("ES256"));
    assertEquals(Optional.empty(), JwsAlgorithm.fromHeader("none"));
    assertEquals(Optional.empty(), JwsAlgorithm.fromHeader(null));
  }

  @Test
  @DisplayName("ClockSkewPolicy rejects a negative leeway")
  void clockSkewNonNegative() {
    assertThrows(IllegalArgumentException.class,
        () -> new ClockSkewPolicy(java.time.Duration.ofSeconds(-1)));
    assertEquals(java.time.Duration.ofSeconds(30), ClockSkewPolicy.DEFAULT.leeway());
  }
}
