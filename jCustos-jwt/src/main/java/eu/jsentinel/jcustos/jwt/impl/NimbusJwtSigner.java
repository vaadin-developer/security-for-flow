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
package eu.jsentinel.jcustos.jwt.impl;

/*-
 * #%L
 * jCustos JWT — standardized JWT validation
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import eu.jsentinel.jcustos.autoservice.api.JCustosAutoService;
import eu.jsentinel.jcustos.jwt.api.JwsAlgorithm;
import eu.jsentinel.jcustos.jwt.api.JwtSigner;
import eu.jsentinel.jcustos.jwt.api.JwtSigningException;
import eu.jsentinel.jcustos.jwt.api.JwtSigningKey;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.Map;
import java.util.Objects;

/**
 * Nimbus-backed {@link JwtSigner} (V00.77, B2). The signing counterpart to
 * {@link NimbusJwtValidator}: RSA/EC are signed via the Nimbus signers, EdDSA
 * (Ed25519) via the JDK's native provider (no Google Tink dependency), exactly
 * mirroring the validator's verification paths. {@code alg:none} and HMAC are
 * impossible — {@link JwsAlgorithm} is asymmetric-only.
 *
 * @since 00.77.00
 */
@JCustosAutoService(JwtSigner.class)
public final class NimbusJwtSigner implements JwtSigner {

  public NimbusJwtSigner() {
  }

  @Override
  public String sign(Map<String, Object> claims, JwtSigningKey key) {
    Objects.requireNonNull(claims, "claims");
    Objects.requireNonNull(key, "key");
    if (claims.isEmpty()) {
      throw new JwtSigningException("jwt-signing/empty-claims", "claims must not be empty");
    }
    JwsAlgorithm alg = key.algorithm();
    PrivateKey privateKey = key.privateKey();
    requireKeyFamily(alg, privateKey);

    JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.parse(alg.name()))
        .type(JOSEObjectType.JWT);
    key.keyId().ifPresent(header::keyID);

    JWTClaimsSet claimsSet;
    try {
      claimsSet = JWTClaimsSet.parse(claims);
    } catch (ParseException e) {
      throw new JwtSigningException("jwt-signing/invalid-claims",
          "claims could not be assembled into a JWT claims set", e);
    }

    SignedJWT jwt = new SignedJWT(header.build(), claimsSet);
    return alg == JwsAlgorithm.EdDSA
        ? signEd25519(jwt, privateKey)
        : signRsaOrEc(jwt, alg, privateKey);
  }

  private static String signRsaOrEc(SignedJWT jwt, JwsAlgorithm alg, PrivateKey privateKey) {
    try {
      JWSSigner signer = switch (alg) {
        case RS256, RS384, RS512, PS256, PS384, PS512 -> new RSASSASigner(privateKey);
        case ES256, ES384, ES512 -> new ECDSASigner((ECPrivateKey) privateKey);
        case EdDSA -> throw new IllegalStateException("EdDSA is signed via the JDK path");
      };
      jwt.sign(signer);
      return jwt.serialize();
    } catch (JOSEException e) {
      throw new JwtSigningException("jwt-signing/sign-failed", "JWS signing failed", e);
    }
  }

  /**
   * Signs an EdDSA (Ed25519) JWS using the JDK's native provider, then assembles
   * the compact form manually — Nimbus's own Ed25519 signer needs Google Tink.
   * The signing input is the unsigned {@code header.payload} byte sequence.
   */
  private static String signEd25519(SignedJWT jwt, PrivateKey privateKey) {
    try {
      byte[] signingInput = jwt.getSigningInput();
      Signature sig = Signature.getInstance("Ed25519");
      sig.initSign(privateKey);
      sig.update(signingInput);
      Base64URL signature = Base64URL.encode(sig.sign());
      return new String(signingInput, StandardCharsets.US_ASCII) + '.' + signature;
    } catch (java.security.GeneralSecurityException e) {
      throw new JwtSigningException("jwt-signing/sign-failed", "Ed25519 signing failed", e);
    }
  }

  private static void requireKeyFamily(JwsAlgorithm alg, PrivateKey key) {
    boolean ok = switch (alg) {
      case RS256, RS384, RS512, PS256, PS384, PS512 -> key instanceof RSAPrivateKey;
      case ES256, ES384, ES512 -> key instanceof ECPrivateKey;
      case EdDSA -> "EdDSA".equalsIgnoreCase(key.getAlgorithm())
          || "Ed25519".equalsIgnoreCase(key.getAlgorithm());
    };
    if (!ok) {
      throw new JwtSigningException("jwt-signing/key-algorithm-mismatch",
          "the private key does not match the " + alg + " algorithm family");
    }
  }
}
