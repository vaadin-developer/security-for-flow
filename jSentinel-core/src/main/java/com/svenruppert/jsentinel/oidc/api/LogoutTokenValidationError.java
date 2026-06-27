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
package com.svenruppert.jsentinel.oidc.api;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.jwt.api.JwtValidationError;

/**
 * Why a Back-Channel Logout token was rejected (V00.79), sealed (OpenID Connect
 * Back-Channel Logout 1.0 §2.4). Each variant has a stable {@link #code()} for
 * diagnostics; none echoes the token.
 *
 * @since 00.79.10
 */
@ExperimentalJSentinelApi
public sealed interface LogoutTokenValidationError {

  String code();

  /** Signature / iss / aud / iat validation of the underlying JWT failed. */
  record JwtInvalid(JwtValidationError cause) implements LogoutTokenValidationError {
    @Override
    public String code() {
      return "logout-token/jwt-invalid";
    }
  }

  /** Neither {@code sub} nor {@code sid} was present (§2.4 step 5). */
  record MissingSubjectAndSid() implements LogoutTokenValidationError {
    @Override
    public String code() {
      return "logout-token/missing-sub-and-sid";
    }
  }

  /**
   * The {@code events} claim did not contain the
   * {@code http://schemas.openid.net/event/backchannel-logout} member (§2.4 step 6),
   * which is what distinguishes a logout token from an ID token.
   */
  record MissingBackchannelEvent() implements LogoutTokenValidationError {
    @Override
    public String code() {
      return "logout-token/missing-backchannel-event";
    }
  }

  /** A {@code nonce} claim was present — forbidden for logout tokens (§2.4 step 7). */
  record NonceMustNotBePresent() implements LogoutTokenValidationError {
    @Override
    public String code() {
      return "logout-token/nonce-present";
    }
  }

  /** The {@code jti} was already seen — replayed logout token. */
  record Replay() implements LogoutTokenValidationError {
    @Override
    public String code() {
      return "logout-token/replay";
    }
  }
}
