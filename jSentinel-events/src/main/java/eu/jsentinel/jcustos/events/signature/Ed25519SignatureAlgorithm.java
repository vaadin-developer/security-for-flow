package eu.jsentinel.jcustos.events.signature;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.SignatureAlgorithmId;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * Default {@link SignatureAlgorithm}: Ed25519 via the JCA
 * {@code Signature.getInstance("Ed25519")} primitive (Konzept §384).
 *
 * <p>Discovered through {@link java.util.ServiceLoader} (see the module's
 * {@code META-INF/services} entry) and wired into
 * {@link SignatureAlgorithms#defaults()}.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class Ed25519SignatureAlgorithm implements SignatureAlgorithm {

  private static final String JCA_NAME = "Ed25519";

  /** Public no-arg constructor for {@link java.util.ServiceLoader}. */
  public Ed25519SignatureAlgorithm() {
  }

  @Override
  public SignatureAlgorithmId id() {
    return SignatureAlgorithmId.ED25519;
  }

  @Override
  public KeyPair generateKeyPair() {
    try {
      return KeyPairGenerator.getInstance(JCA_NAME).generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new SignatureOperationException("Ed25519 key generation unavailable", e);
    }
  }

  @Override
  public byte[] sign(byte[] data, PrivateKey privateKey) {
    try {
      Signature signature = Signature.getInstance(JCA_NAME);
      signature.initSign(privateKey);
      signature.update(data);
      return signature.sign();
    } catch (GeneralSecurityException e) {
      throw new SignatureOperationException("Ed25519 signing failed", e);
    }
  }

  @Override
  public boolean verify(byte[] data, byte[] signature, PublicKey publicKey) {
    try {
      Signature verifier = Signature.getInstance(JCA_NAME);
      verifier.initVerify(publicKey);
      verifier.update(data);
      return verifier.verify(signature);
    } catch (SignatureException e) {
      // structurally invalid signature bytes — not a configuration error
      return false;
    } catch (GeneralSecurityException e) {
      throw new SignatureOperationException("Ed25519 verification failed", e);
    }
  }
}
