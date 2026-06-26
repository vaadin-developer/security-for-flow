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
 * @param expectedTyp      F4 (V00.76.10): optional {@code typ} header media type
 *                         (e.g. {@code "at+jwt"}). When present, a token whose
 *                         {@code typ} header is absent or does not match is
 *                         rejected (RFC 8725 §3.11, cross-JWT-type confusion).
 *                         Empty by default — the {@code typ} header is not checked
 *                         unless an expected type is configured. The comparison is
 *                         case-insensitive and tolerates an {@code application/}
 *                         prefix.
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
    ClockSkewPolicy skewPolicy,
    Optional<String> expectedTyp) {

  public ClaimExpectations {
    expectedIssuer = Objects.requireNonNull(expectedIssuer, "expectedIssuer");
    acceptedAudiences = Set.copyOf(Objects.requireNonNull(acceptedAudiences, "acceptedAudiences"));
    skewPolicy = Objects.requireNonNull(skewPolicy, "skewPolicy");
    expectedTyp = Objects.requireNonNull(expectedTyp, "expectedTyp");
  }

  /**
   * Backward-compatible constructor (pre-F4) — no {@code typ} expectation, so the
   * {@code typ} header is not checked. Equivalent to passing
   * {@code Optional.empty()} as {@code expectedTyp}.
   */
  public ClaimExpectations(
      Optional<String> expectedIssuer,
      Set<String> acceptedAudiences,
      boolean requireExp,
      boolean requireNbf,
      boolean requireIat,
      boolean requireJti,
      ClockSkewPolicy skewPolicy) {
    this(expectedIssuer, acceptedAudiences, requireExp, requireNbf, requireIat,
        requireJti, skewPolicy, Optional.empty());
  }
}
