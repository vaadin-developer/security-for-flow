package eu.jsentinel.jcustos.jwt.api;

import java.util.Objects;

/**
 * The sealed set of reasons a JWT validation fails. Every variant exposes a
 * stable, machine-readable {@link #code()} (kebab-case) and a human-readable
 * {@link #message()} that carries no PII and no secret material.
 *
 * @since 00.76.00
 */
public sealed interface JwtValidationError
    permits JwtValidationError.MalformedJwt, JwtValidationError.SignatureInvalid,
            JwtValidationError.UnsupportedAlgorithm, JwtValidationError.UnknownKid,
            JwtValidationError.Expired, JwtValidationError.NotYetValid,
            JwtValidationError.ClaimInvalid, JwtValidationError.JweNotSupported {

  /** @return the stable machine-readable error code (kebab-case). */
  String code();

  /** @return a human-readable, PII-free, secret-free message. */
  String message();

  /** The compact form is not a well-formed JWS (wrong segment count, bad Base64URL …). */
  record MalformedJwt(String message) implements JwtValidationError {
    public MalformedJwt {
      Objects.requireNonNull(message, "message");
    }

    @Override
    public String code() {
      return "jwt/malformed";
    }
  }

  /** The signature did not verify against the resolved key. */
  record SignatureInvalid(String message) implements JwtValidationError {
    public SignatureInvalid {
      Objects.requireNonNull(message, "message");
    }

    @Override
    public String code() {
      return "jwt/signature-invalid";
    }
  }

  /**
   * The header {@code alg} is not acceptable. The {@code code} distinguishes the
   * sub-case: {@code jwt/algorithm-not-in-allow-list},
   * {@code jwt/algorithm-confusion-suspected} or {@code jwt/algorithm-none-attempted}.
   */
  record UnsupportedAlgorithm(String code, String message) implements JwtValidationError {
    public UnsupportedAlgorithm {
      Objects.requireNonNull(code, "code");
      Objects.requireNonNull(message, "message");
    }
  }

  /** No key for the header {@code kid} after a single refresh. */
  record UnknownKid(String message) implements JwtValidationError {
    public UnknownKid {
      Objects.requireNonNull(message, "message");
    }

    @Override
    public String code() {
      return "jwt/unknown-kid";
    }
  }

  /** {@code exp} is in the past (beyond the configured skew). */
  record Expired(String message) implements JwtValidationError {
    public Expired {
      Objects.requireNonNull(message, "message");
    }

    @Override
    public String code() {
      return "jwt/expired";
    }
  }

  /** {@code nbf} is in the future (beyond the configured skew). */
  record NotYetValid(String message) implements JwtValidationError {
    public NotYetValid {
      Objects.requireNonNull(message, "message");
    }

    @Override
    public String code() {
      return "jwt/not-yet-valid";
    }
  }

  /**
   * A standard claim failed validation. The {@code code} names the sub-case, e.g.
   * {@code claims/issuer-mismatch}, {@code claims/audience-mismatch} or
   * {@code claims/exp-missing}.
   */
  record ClaimInvalid(String code, String message) implements JwtValidationError {
    public ClaimInvalid {
      Objects.requireNonNull(code, "code");
      Objects.requireNonNull(message, "message");
    }
  }

  /** The token is a JWE (five segments). V00.76 rejects encrypted JWTs. */
  record JweNotSupported(String message) implements JwtValidationError {
    public JweNotSupported {
      Objects.requireNonNull(message, "message");
    }

    @Override
    public String code() {
      return "jwt/jwe-not-supported";
    }
  }
}
