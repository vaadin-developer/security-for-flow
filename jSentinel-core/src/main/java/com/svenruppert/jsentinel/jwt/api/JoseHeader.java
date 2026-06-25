package com.svenruppert.jsentinel.jwt.api;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.util.Objects;
import java.util.Optional;

/**
 * The parsed, still-<em>untrusted</em> JOSE header of a compact JWT. {@code alg}
 * and {@code kid} are read before the signature is verified, so they may only be
 * used to select a verification routine / key — never trusted as authorization
 * input.
 *
 * @param alg the raw {@code alg} value (required; an absent alg is malformed)
 * @param kid the optional key id
 * @param typ the optional token type
 * @since 00.76.00
 */
@ExperimentalJSentinelApi
public record JoseHeader(String alg, Optional<String> kid, Optional<String> typ) {

  public JoseHeader {
    Objects.requireNonNull(alg, "alg");
    kid = Objects.requireNonNull(kid, "kid");
    typ = Objects.requireNonNull(typ, "typ");
  }
}
