package eu.jsentinel.jcustos.events.signature;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.events.api.SignatureAlgorithmId;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;

/**
 * Optional fallback {@link SignatureAlgorithm}: {@code SHA256withECDSA} over
 * the NIST P-256 curve (Konzept §390). Provided for JDK distributions where
 * Ed25519 is unavailable. Opt-in — it is registered for
 * {@link java.util.ServiceLoader} discovery but the modern default stays
 * Ed25519.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class EcdsaP256SignatureAlgorithm implements SignatureAlgorithm {

  private static final String JCA_SIGNATURE = "SHA256withECDSA";
  private static final String JCA_KEY = "EC";
  private static final String CURVE = "secp256r1";

  /** Public no-arg constructor for {@link java.util.ServiceLoader}. */
  public EcdsaP256SignatureAlgorithm() {
  }

  @Override
  public SignatureAlgorithmId id() {
    return SignatureAlgorithmId.ECDSA_P256;
  }

  @Override
  public KeyPair generateKeyPair() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance(JCA_KEY);
      generator.initialize(new ECGenParameterSpec(CURVE));
      return generator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new SignatureOperationException("EC P-256 key generation unavailable", e);
    }
  }

  @Override
  public byte[] sign(byte[] data, PrivateKey privateKey) {
    try {
      Signature signature = Signature.getInstance(JCA_SIGNATURE);
      signature.initSign(privateKey);
      signature.update(data);
      return signature.sign();
    } catch (GeneralSecurityException e) {
      throw new SignatureOperationException("SHA256withECDSA signing failed", e);
    }
  }

  @Override
  public boolean verify(byte[] data, byte[] signature, PublicKey publicKey) {
    try {
      Signature verifier = Signature.getInstance(JCA_SIGNATURE);
      verifier.initVerify(publicKey);
      verifier.update(data);
      return verifier.verify(signature);
    } catch (SignatureException e) {
      return false;
    } catch (GeneralSecurityException e) {
      throw new SignatureOperationException("SHA256withECDSA verification failed", e);
    }
  }
}
