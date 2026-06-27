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
package com.svenruppert.jsentinel.dpop;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Produces an outbound DPoP proof JWS (RFC 9449 §4.2), V00.79. The proof header carries
 * {@code typ=dpop+jwt} and the public half of the signing key; the body carries a fresh
 * {@code jti}, {@code htm} (method), {@code htu} (request URI without query/fragment),
 * {@code iat}, and — when bound to an access token at a resource server — {@code ath}
 * (the base64url SHA-256 of that token). Pair with {@link NimbusDpopProofValidator}.
 *
 * @since 00.79.10
 */
@ExperimentalJSentinelApi
public final class DpopProofGenerator {

  /** RFC 9449 §4.2: the DPoP-proof JOSE {@code typ}. */
  public static final JOSEObjectType DPOP_JWT_TYPE = new JOSEObjectType("dpop+jwt");

  private final Supplier<Instant> clock;
  private final Supplier<String> jtiSource;

  public DpopProofGenerator() {
    this(Instant::now, () -> UUID.randomUUID().toString());
  }

  public DpopProofGenerator(Supplier<Instant> clock, Supplier<String> jtiSource) {
    this.clock = Objects.requireNonNull(clock, "clock");
    this.jtiSource = Objects.requireNonNull(jtiSource, "jtiSource");
  }

  /**
   * Signs a DPoP proof for {@code htm htu} with {@code signingKey} (which MUST contain
   * the private key); when {@code accessToken} is present an {@code ath} claim binds the
   * proof to it.
   */
  public String generate(JWK signingKey, String httpMethod, URI httpUri, Optional<String> accessToken) {
    Objects.requireNonNull(signingKey, "signingKey");
    Objects.requireNonNull(httpMethod, "httpMethod");
    Objects.requireNonNull(httpUri, "httpUri");
    Objects.requireNonNull(accessToken, "accessToken");
    if (!signingKey.isPrivate()) {
      throw new IllegalArgumentException("signingKey must contain a private key to sign a proof");
    }
    JWSAlgorithm alg = algorithmFor(signingKey);
    JWSHeader header = new JWSHeader.Builder(alg)
        .type(DPOP_JWT_TYPE)
        .jwk(signingKey.toPublicJWK())
        .build();

    JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
        .jwtID(jtiSource.get())
        .claim("htm", httpMethod)
        .claim("htu", DpopHttpUri.normalize(httpUri))
        .issueTime(Date.from(clock.get()));
    accessToken.ifPresent(token -> claims.claim("ath", accessTokenHash(token)));

    try {
      SignedJWT jws = new SignedJWT(header, claims.build());
      jws.sign(signerFor(signingKey));
      return jws.serialize();
    } catch (JOSEException e) {
      throw new IllegalStateException("failed to sign DPoP proof", e);
    }
  }

  private static JWSAlgorithm algorithmFor(JWK key) {
    if (key instanceof RSAKey) {
      return JWSAlgorithm.RS256;
    }
    if (key instanceof ECKey) {
      return JWSAlgorithm.ES256;
    }
    throw new IllegalArgumentException("unsupported DPoP key type: " + key.getKeyType());
  }

  private static JWSSigner signerFor(JWK key) {
    try {
      if (key instanceof RSAKey rsa) {
        return new RSASSASigner(rsa);
      }
      if (key instanceof ECKey ec) {
        return new ECDSASigner(ec);
      }
    } catch (JOSEException e) {
      throw new IllegalStateException("failed to build DPoP signer", e);
    }
    throw new IllegalArgumentException("unsupported DPoP key type: " + key.getKeyType());
  }

  static String accessTokenHash(String accessToken) {
    try {
      MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
      byte[] digest = sha256.digest(accessToken.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
      return Base64URL.encode(digest).toString();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }
}
