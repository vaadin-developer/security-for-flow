/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.credential.propagation;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

import java.time.Instant;
import java.util.Optional;

/**
 * Sealed type for inbound / outbound tokens flowing through the V00.74
 * token-propagation pipeline.
 *
 * <p>Four permits cover the realistic shapes:
 * <ul>
 *   <li>{@link BearerToken} — opaque bearer token carried in
 *       {@code Authorization: Bearer …}.</li>
 *   <li>{@link OidcAccessToken} — OIDC access token, semantically a
 *       bearer with an issuer claim.</li>
 *   <li>{@link RefreshToken} — class-A refresh secret; never forwarded by
 *       {@code PassThroughStrategy}.</li>
 *   <li>{@link ApiKey} — opaque API key; transport-specific header
 *       handling (consumers register their own strategy).</li>
 * </ul>
 *
 * <p><strong>Logging discipline.</strong> {@link #value()} returns the raw
 * token. It must never be:
 * <ul>
 *   <li>written to any logger,</li>
 *   <li>recorded in any {@code AuditEvent},</li>
 *   <li>persisted to any store outside the
 *       {@code TokenCredentialStore} contract.</li>
 * </ul>
 * Every record implementation masks the value in {@code toString()}
 * (e.g. {@code "BearerToken{exp=…, aud=…, value=***}"}).
 *
 * <p>V00.74 ships this type tagged {@link ExperimentalJSentinelApi};
 * stable-API promotion is staged for V00.76 after at least one demo
 * migration cycle.
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi("V00.74 token propagation; stable promotion staged for V00.76")
public sealed interface TokenCredential
    permits BearerToken, OidcAccessToken, RefreshToken, ApiKey {

  /**
   * The raw token string.
   *
   * <p><strong>Never log, never audit, never persist outside the
   * {@code TokenCredentialStore}.</strong> Treated as a Class-A secret.
   *
   * @return the raw token value (non-null, non-empty by construction)
   */
  String value();

  /**
   * JS-SEC-044 (CWE-522): whether this credential may be forwarded to a downstream service or a
   * token-exchange endpoint as a bearer / {@code subject_token}. The two Class-A secrets —
   * {@link RefreshToken} and {@link ApiKey} — must <strong>never</strong> be forwarded (they would
   * leak via the outbound call, and mislabeling a refresh secret as an access token is worse); only
   * access-token-shaped credentials ({@link BearerToken}, {@link OidcAccessToken}) are forwardable.
   * This is the single source of truth every propagation strategy consults, so the pass-through and
   * token-exchange strategies cannot drift.
   *
   * @return {@code true} if this credential is safe to forward as a bearer subject token
   */
  default boolean isForwardableAsSubjectToken() {
    return this instanceof BearerToken || this instanceof OidcAccessToken;
  }

  /**
   * @return wall-clock expiry of the token, if known
   */
  Optional<Instant> expiresAt();

  /**
   * @return declared audience of the token, if known
   */
  Optional<String> audience();

  /**
   * @return SHA-256 hex of the issuer (e.g. issuer URL), for audit
   *         metadata only — never the issuer URL itself in clear text
   */
  Optional<String> issuerHash();
}
