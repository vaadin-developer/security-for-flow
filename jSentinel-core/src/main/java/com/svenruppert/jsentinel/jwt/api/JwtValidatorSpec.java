package com.svenruppert.jsentinel.jwt.api;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.net.URI;
import java.util.Objects;

/**
 * The declarative inputs a {@link JwtValidatorFactory} needs to assemble a
 * validator: where to fetch keys ({@code jwksUri}), which algorithms to accept
 * ({@code allowList}) and what to require of the claims ({@code expectations}).
 *
 * <p>This is the seam that keeps {@code jSentinel-dx} JOSE-free: the DX bootstrap
 * builds a spec from the {@code .jwt(...)} sub-builder and hands it to the
 * ServiceLoader-discovered factory, never touching a Nimbus type itself.
 *
 * @param jwksUri      the JWKS endpoint (must be absolute; https enforced by impl)
 * @param allowList    the mandatory algorithm allow-list
 * @param expectations the claim expectations
 * @since 00.76.00
 */
@ExperimentalJSentinelApi
public record JwtValidatorSpec(
    URI jwksUri,
    AlgorithmAllowList allowList,
    ClaimExpectations expectations) {

  public JwtValidatorSpec {
    Objects.requireNonNull(jwksUri, "jwksUri");
    allowList = Objects.requireNonNull(allowList, "allowList");
    expectations = Objects.requireNonNull(expectations, "expectations");
  }
}
