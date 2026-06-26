package com.svenruppert.jsentinel.dx.bootstrap;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.oauth2.api.ClientAuthentication;
import com.svenruppert.jsentinel.oauth2.api.RefreshTokenFamilyStore;
import com.svenruppert.jsentinel.oauth2.api.StateStore;

import java.net.URI;
import java.time.Duration;

/**
 * V00.77 declarative OAuth2 Relying-Party sub-builder, exposed via
 * {@code .oauth2(...)} on {@link CommonJSentinelBootstrap}; all three adapter
 * facades inherit it (adapter symmetry — Vaadin uses the redirect/callback flow,
 * REST the callback handler, Standalone the device grant). The DX layer only
 * records + validates the configuration (Konzept §11); the actual HTTP clients
 * are assembled in the {@code jSentinel-oauth2-*} adapter modules, so this layer
 * stays free of any JOSE / HTTP-client compile dependency.
 *
 * <p>STRICT mode raises for {@code oauth2/missing-client-id},
 * {@code oauth2/missing-token-endpoint} and {@code oauth2/redirect-uri-not-https};
 * an empty {@link #scope(String...)} is an INFO finding only.
 *
 * @since 00.77.00
 */
@ExperimentalJSentinelApi
public interface OAuth2Bootstrap {

  /** The RP's {@code client_id} (required — STRICT raises {@code oauth2/missing-client-id}). */
  OAuth2Bootstrap clientId(String clientId);

  /** How the RP authenticates to the token endpoint (default: public client + PKCE). */
  OAuth2Bootstrap clientAuthentication(ClientAuthentication auth);

  /** The authorization endpoint (start of the redirect flow). */
  OAuth2Bootstrap authorizationEndpoint(URI uri);

  /** The token endpoint (required — STRICT raises {@code oauth2/missing-token-endpoint}). */
  OAuth2Bootstrap tokenEndpoint(URI uri);

  /** The RFC 7009 revocation endpoint. */
  OAuth2Bootstrap revocationEndpoint(URI uri);

  /** The RFC 7662 introspection endpoint. */
  OAuth2Bootstrap introspectionEndpoint(URI uri);

  /** The RFC 8628 device-authorization endpoint. */
  OAuth2Bootstrap deviceAuthorizationEndpoint(URI uri);

  /** The registered redirect URI (must be https or http://localhost* — STRICT-checked). */
  OAuth2Bootstrap redirectUri(URI uri);

  /** The requested scopes (empty → INFO {@code oauth2/scope-empty}). */
  OAuth2Bootstrap scope(String... scopes);

  /** Whether PKCE is required (default true; S256 only). */
  OAuth2Bootstrap pkceRequired(boolean required);

  /** Whether refresh tokens rotate with reuse-detection (default true). */
  OAuth2Bootstrap refreshTokenRotation(boolean rotate);

  /** The state / PKCE-verifier store (adapter default when omitted). */
  OAuth2Bootstrap stateStore(StateStore store);

  /** The TTL for bound state entries. */
  OAuth2Bootstrap stateTtl(Duration ttl);

  /** The refresh-token family store backing reuse-detection. */
  OAuth2Bootstrap refreshTokenFamilyStore(RefreshTokenFamilyStore store);

  /** The introspection-decision cache TTL. */
  OAuth2Bootstrap introspectionCacheTtl(Duration ttl);
}
