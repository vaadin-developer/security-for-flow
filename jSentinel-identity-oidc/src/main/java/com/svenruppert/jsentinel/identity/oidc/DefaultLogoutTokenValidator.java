/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.jsentinel.identity.oidc;

/*-
 * #%L
 * jSentinel OIDC — Relying-Party identity layer
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.functional.result.Result;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.jwt.api.JwtValidationError;
import com.svenruppert.jsentinel.jwt.api.JwtValidator;
import com.svenruppert.jsentinel.jwt.api.ValidatedJwt;
import com.svenruppert.jsentinel.oidc.api.BackChannelLogoutToken;
import com.svenruppert.jsentinel.oidc.api.LogoutTokenValidationError;
import com.svenruppert.jsentinel.oidc.api.LogoutTokenValidator;
import com.svenruppert.jsentinel.replay.api.JtiStore;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Default {@link LogoutTokenValidator} (V00.79). Composition, not inheritance: it wraps
 * a V00.76 {@link JwtValidator} (configured by the caller with the OP issuer + RP client
 * id as audience) for signature / iss / aud / iat, then applies the four
 * logout-token-specific checks of OpenID Connect Back-Channel Logout 1.0 §2.4:
 * the {@code events} back-channel-logout member, {@code sub}/{@code sid} presence,
 * {@code nonce} absence, and (via the optional {@link JtiStore}) single-use of
 * {@code jti}.
 *
 * @since 00.79.10
 */
@ExperimentalJSentinelApi
public final class DefaultLogoutTokenValidator implements LogoutTokenValidator {

  /** OIDC Back-Channel Logout 1.0 §2.4: the required {@code events} member. */
  public static final String BACKCHANNEL_LOGOUT_EVENT =
      "http://schemas.openid.net/event/backchannel-logout";

  private static final Duration JTI_RETENTION = Duration.ofMinutes(10);

  private final JwtValidator jwtValidator;
  private final Optional<JtiStore> jtiStore;

  public DefaultLogoutTokenValidator(JwtValidator jwtValidator) {
    this(jwtValidator, Optional.empty());
  }

  public DefaultLogoutTokenValidator(JwtValidator jwtValidator, JtiStore jtiStore) {
    this(jwtValidator, Optional.of(jtiStore));
  }

  private DefaultLogoutTokenValidator(JwtValidator jwtValidator, Optional<JtiStore> jtiStore) {
    this.jwtValidator = Objects.requireNonNull(jwtValidator, "jwtValidator");
    this.jtiStore = Objects.requireNonNull(jtiStore, "jtiStore");
  }

  @Override
  public Result<BackChannelLogoutToken, LogoutTokenValidationError> validate(String compactLogoutToken) {
    Objects.requireNonNull(compactLogoutToken, "compactLogoutToken");

    Result<ValidatedJwt, JwtValidationError> jwtResult = jwtValidator.validate(compactLogoutToken);
    Optional<ValidatedJwt> ok = jwtResult.toOptional();
    if (ok.isEmpty()) {
      return Result.failure(new LogoutTokenValidationError.JwtInvalid(jwtResult.fold(v -> null, e -> e)));
    }
    ValidatedJwt jwt = ok.get();

    // §2.4 step 7 — a nonce MUST NOT be present (this is what tells a logout token from an ID token).
    if (jwt.claim("nonce", Object.class).isPresent()) {
      return Result.failure(new LogoutTokenValidationError.NonceMustNotBePresent());
    }

    // §2.4 step 6 — the events claim must contain the back-channel-logout member.
    Optional<Map> events = jwt.claim("events", Map.class);
    if (events.isEmpty() || !events.get().containsKey(BACKCHANNEL_LOGOUT_EVENT)) {
      return Result.failure(new LogoutTokenValidationError.MissingBackchannelEvent());
    }

    // §2.4 step 5 — sub and/or sid.
    Optional<String> subject = jwt.claim("sub", String.class);
    Optional<String> sid = jwt.claim("sid", String.class);
    if (subject.isEmpty() && sid.isEmpty()) {
      return Result.failure(new LogoutTokenValidationError.MissingSubjectAndSid());
    }

    // §2.4 step 1 — jti is REQUIRED. Reject its absence rather than silently skipping
    // replay protection (a jti-less token would otherwise be infinitely replayable).
    Optional<String> jti = jwt.jwtId();
    if (jti.isEmpty() || jti.get().isBlank()) {
      return Result.failure(new LogoutTokenValidationError.MissingJwtId());
    }

    String issuer = jwt.issuer().orElse("");
    if (jtiStore.isPresent()) {
      Instant expiresAt = jwt.issuedAt().orElse(Instant.EPOCH).plus(JTI_RETENTION);
      if (!jtiStore.get().record(jti.get(), expiresAt).isSuccess()) {
        return Result.failure(new LogoutTokenValidationError.Replay());
      }
    }

    return Result.success(new BackChannelLogoutToken(issuer, subject, sid, jti.get()));
  }
}
