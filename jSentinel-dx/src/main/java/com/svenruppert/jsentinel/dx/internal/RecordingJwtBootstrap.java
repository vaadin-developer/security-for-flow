package com.svenruppert.jsentinel.dx.internal;

import com.svenruppert.jsentinel.dx.bootstrap.JwtBootstrap;
import com.svenruppert.jsentinel.jwt.api.AlgorithmAllowList;
import com.svenruppert.jsentinel.jwt.api.AlgorithmProfile;
import com.svenruppert.jsentinel.jwt.api.JwtValidator;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

/**
 * Default {@link JwtBootstrap} that records the chain into a {@link JwtState}.
 * Mutually-exclusive configurations raise here, at configuration time, rather
 * than being deferred — matching the {@code RecordingPropagationBootstrap}
 * pattern.
 *
 * @since 00.76.00
 */
public final class RecordingJwtBootstrap implements JwtBootstrap {

  private final JwtState state;

  public RecordingJwtBootstrap(JwtState state) {
    this.state = Objects.requireNonNull(state, "state");
  }

  @Override
  public JwtBootstrap validator(JwtValidator validator) {
    Objects.requireNonNull(validator, "validator");
    if (state.jwksUri() != null) {
      throw new IllegalStateException("jwt/conflicting-validator-config: .jwksUri(...) already set; "
          + "remove either .jwksUri(...) or .validator(...) — pick one.");
    }
    state.validator(validator);
    return this;
  }

  @Override
  public JwtBootstrap jwksUri(URI jwksUri) {
    Objects.requireNonNull(jwksUri, "jwksUri");
    if (state.validator() != null) {
      throw new IllegalStateException("jwt/conflicting-validator-config: .validator(...) already set; "
          + "remove either .validator(...) or .jwksUri(...) — pick one.");
    }
    state.jwksUri(jwksUri);
    return this;
  }

  @Override
  public JwtBootstrap algorithmProfile(AlgorithmProfile profile) {
    Objects.requireNonNull(profile, "profile");
    if (state.allowList() != null) {
      throw new IllegalStateException("jwt/conflicting-algorithm-config: .algorithmAllowList(...) "
          + "already set; remove either it or .algorithmProfile(...) — pick one.");
    }
    state.profile(profile);
    return this;
  }

  @Override
  public JwtBootstrap algorithmAllowList(AlgorithmAllowList allowList) {
    Objects.requireNonNull(allowList, "allowList");
    if (state.profile() != null) {
      throw new IllegalStateException("jwt/conflicting-algorithm-config: .algorithmProfile(...) "
          + "already set; remove either it or .algorithmAllowList(...) — pick one.");
    }
    state.allowList(allowList);
    return this;
  }

  @Override
  public JwtBootstrap issuer(String expectedIssuer) {
    state.issuer(Objects.requireNonNull(expectedIssuer, "expectedIssuer"));
    return this;
  }

  @Override
  public JwtBootstrap audience(String... acceptedAudiences) {
    state.addAudiences(Objects.requireNonNull(acceptedAudiences, "acceptedAudiences"));
    return this;
  }

  @Override
  public JwtBootstrap clockSkew(Duration leeway) {
    state.clockSkew(Objects.requireNonNull(leeway, "leeway"));
    return this;
  }

  @Override
  public JwtBootstrap tokenType(String tokenType) {
    state.tokenType(Objects.requireNonNull(tokenType, "tokenType"));
    return this;
  }
}
