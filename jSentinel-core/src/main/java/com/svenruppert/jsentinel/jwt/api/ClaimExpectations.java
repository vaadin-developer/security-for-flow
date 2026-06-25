package com.svenruppert.jsentinel.jwt.api;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * What the validator requires of a token's standard claims (RFC 7519 §4).
 *
 * @param expectedIssuer   exact-match issuer, if present; never {@code endsWith}
 *                         / {@code contains}
 * @param acceptedAudiences allowed {@code aud} values (intersection check); an
 *                         empty set accepts any audience (with a bootstrap INFO)
 * @param requireExp       fail if {@code exp} is absent
 * @param requireNbf       fail if {@code nbf} is absent
 * @param requireIat       fail if {@code iat} is absent (existence only — not
 *                         checked against future skew)
 * @param requireJti       fail if {@code jti} is absent (existence only in V00.76;
 *                         replay defence is V00.79)
 * @param skewPolicy       the clock-skew leeway for {@code exp} / {@code nbf}
 * @since 00.76.00
 */
@ExperimentalJSentinelApi
public record ClaimExpectations(
    Optional<String> expectedIssuer,
    Set<String> acceptedAudiences,
    boolean requireExp,
    boolean requireNbf,
    boolean requireIat,
    boolean requireJti,
    ClockSkewPolicy skewPolicy) {

  public ClaimExpectations {
    expectedIssuer = Objects.requireNonNull(expectedIssuer, "expectedIssuer");
    acceptedAudiences = Set.copyOf(Objects.requireNonNull(acceptedAudiences, "acceptedAudiences"));
    skewPolicy = Objects.requireNonNull(skewPolicy, "skewPolicy");
  }
}
