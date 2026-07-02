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

import com.svenruppert.jsentinel.jwt.api.JwtValidationError;

import java.util.Objects;

/**
 * A non-secret OIDC ID-token validation failure (V00.78). Extends the JWT-standard
 * failures (wrapped via {@link JwtInvalid}) with the OIDC-specific checks from
 * OIDC Core §3.1.3.7. Every variant exposes a stable kebab-case {@link #code()};
 * no token, claim value or secret is ever carried in the message.
 *
 * @since 00.78.00
 */
public sealed interface IdTokenValidationError
    permits IdTokenValidationError.JwtInvalid, IdTokenValidationError.NonceMismatch,
            IdTokenValidationError.AuthorizedPartyInvalid, IdTokenValidationError.AccessTokenHashMismatch,
            IdTokenValidationError.CodeHashMismatch, IdTokenValidationError.AuthTimeStale,
            IdTokenValidationError.AcrUnsatisfied, IdTokenValidationError.IssuerMismatch,
            IdTokenValidationError.AudienceMismatch {

  /** @return a stable kebab-case error code. */
  String code();

  /** The underlying JWT-standard validation failed (signature, exp, iss, aud, …). */
  record JwtInvalid(JwtValidationError cause) implements IdTokenValidationError {
    public JwtInvalid {
      Objects.requireNonNull(cause, "cause");
    }

    @Override
    public String code() {
      return "oidc/jwt-invalid";
    }
  }

  /** The {@code nonce} claim did not match the one bound at authorization time. */
  record NonceMismatch() implements IdTokenValidationError {
    @Override
    public String code() {
      return "oidc/nonce-mismatch";
    }
  }

  /** {@code azp} was required (multi-audience or present) and did not match the client. */
  record AuthorizedPartyInvalid() implements IdTokenValidationError {
    @Override
    public String code() {
      return "oidc/azp-invalid";
    }
  }

  /** The {@code at_hash} claim did not match the access token (OIDC §3.1.3.6). */
  record AccessTokenHashMismatch() implements IdTokenValidationError {
    @Override
    public String code() {
      return "oidc/at-hash-mismatch";
    }
  }

  /** The {@code c_hash} claim did not match the authorization code (hybrid flow). */
  record CodeHashMismatch() implements IdTokenValidationError {
    @Override
    public String code() {
      return "oidc/c-hash-mismatch";
    }
  }

  /** {@code auth_time} is older than the requested {@code max_age} — re-authentication needed. */
  record AuthTimeStale() implements IdTokenValidationError {
    @Override
    public String code() {
      return "oidc/auth-time-stale";
    }
  }

  /** The {@code acr} claim is not among the requested authentication-context classes. */
  record AcrUnsatisfied() implements IdTokenValidationError {
    @Override
    public String code() {
      return "oidc/acr-unsatisfied";
    }
  }

  /** The {@code iss} claim did not equal the expected issuer (OIDC-layer backstop). */
  record IssuerMismatch() implements IdTokenValidationError {
    @Override
    public String code() {
      return "oidc/issuer-mismatch";
    }
  }

  /** The {@code aud} claim did not contain the expected audience (OIDC-layer backstop). */
  record AudienceMismatch() implements IdTokenValidationError {
    @Override
    public String code() {
      return "oidc/audience-mismatch";
    }
  }
}
