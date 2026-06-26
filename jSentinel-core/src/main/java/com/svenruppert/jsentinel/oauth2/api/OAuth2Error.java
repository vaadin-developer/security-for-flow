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
package com.svenruppert.jsentinel.oauth2.api;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.util.Objects;

/**
 * Sealed failure of an OAuth2 RP operation (V00.77). Each variant carries a
 * stable kebab-case {@link #code()} and a short, non-secret {@link #message()};
 * the raw {@code error_description} from a token/introspection endpoint is never
 * propagated verbatim (it can echo internals), and no token value ever appears.
 *
 * @since 00.77.00
 */
@ExperimentalJSentinelApi
public sealed interface OAuth2Error
    permits OAuth2Error.ProtocolError, OAuth2Error.StateInvalid,
            OAuth2Error.AuthorizationDenied, OAuth2Error.RefreshTokenFamilyRevoked,
            OAuth2Error.DeviceCodeExpired, OAuth2Error.EndpointError,
            OAuth2Error.NetworkError, OAuth2Error.MalformedResponse {

  /** @return a stable kebab-case error code. */
  String code();

  /** @return a short, non-secret description. */
  String message();

  /**
   * A standard RFC 6749 §5.2 token-endpoint error (e.g. {@code invalid_grant},
   * {@code invalid_client}, {@code unauthorized_client}, {@code invalid_scope}).
   *
   * @param oauthError the RFC error identifier as returned by the endpoint
   */
  record ProtocolError(String oauthError) implements OAuth2Error {
    public ProtocolError {
      Objects.requireNonNull(oauthError, "oauthError");
    }

    @Override
    public String code() {
      return "oauth2/protocol-error:" + oauthError;
    }

    @Override
    public String message() {
      return "token endpoint rejected the request: " + oauthError;
    }
  }

  /** The {@code state} on a callback was unknown, already consumed, or expired. */
  record StateInvalid(String detail) implements OAuth2Error {
    @Override
    public String code() {
      return "oauth2/state-invalid-or-expired";
    }

    @Override
    public String message() {
      return "the authorization state could not be validated";
    }
  }

  /** The authorization endpoint returned an {@code error} on the callback (user denied / IdP error). */
  record AuthorizationDenied(String oauthError) implements OAuth2Error {
    @Override
    public String code() {
      return "oauth2/authorization-denied";
    }

    @Override
    public String message() {
      return "authorization was denied at the IdP";
    }
  }

  /** A reused refresh token was presented; the whole token family was revoked (BCP 9700 §4.13.2). */
  record RefreshTokenFamilyRevoked() implements OAuth2Error {
    @Override
    public String code() {
      return "oauth2/refresh-token-family-revoked";
    }

    @Override
    public String message() {
      return "refresh-token reuse detected — the token family was revoked";
    }
  }

  /** A device-authorization grant exceeded its {@code expires_in} without approval. */
  record DeviceCodeExpired() implements OAuth2Error {
    @Override
    public String code() {
      return "oauth2/device-code-expired";
    }

    @Override
    public String message() {
      return "the device code expired before authorization";
    }
  }

  /** A non-2xx HTTP status from an OAuth2 endpoint (no parseable OAuth2 error body). */
  record EndpointError(int statusCode) implements OAuth2Error {
    @Override
    public String code() {
      return "oauth2/endpoint-error";
    }

    @Override
    public String message() {
      return "OAuth2 endpoint returned HTTP " + statusCode;
    }
  }

  /** A transport failure (timeout, connection reset, TLS) reaching an OAuth2 endpoint. */
  record NetworkError(String kind) implements OAuth2Error {
    @Override
    public String code() {
      return "oauth2/network-error";
    }

    @Override
    public String message() {
      return "could not reach the OAuth2 endpoint (" + kind + ")";
    }
  }

  /** A 2xx response whose body was not a parseable token/introspection response. */
  record MalformedResponse(String detail) implements OAuth2Error {
    @Override
    public String code() {
      return "oauth2/malformed-response";
    }

    @Override
    public String message() {
      return "the OAuth2 endpoint response was malformed";
    }
  }
}
