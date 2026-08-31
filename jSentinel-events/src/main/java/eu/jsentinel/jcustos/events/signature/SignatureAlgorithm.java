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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * SPI for an asymmetric signature algorithm used to sign and verify
 * {@link eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope}
 * signature bases (Konzept §346-§403).
 *
 * <p>The bus signs with a private key and verifies with the matching public
 * key, so a consumer can authenticate events without being able to forge them
 * (Konzept §397). The interface is an open SPI: the two built-in providers
 * ({@code Ed25519}, {@code SHA256withECDSA}) ship with the module and are
 * wired in {@link SignatureAlgorithms#defaults()}; third-party algorithms can
 * be contributed through {@link java.util.ServiceLoader}.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public interface SignatureAlgorithm {

  /**
   * @return the stable wire identifier stored on the envelope
   */
  SignatureAlgorithmId id();

  /**
   * Generates a fresh key pair compatible with this algorithm. Useful for
   * tests and for the key-management layer's bootstrap path.
   *
   * @return a new key pair
   */
  KeyPair generateKeyPair();

  /**
   * Signs the given data.
   *
   * @param data the signature base bytes
   * @param privateKey the signing key
   * @return the signature bytes
   * @throws SignatureOperationException if the JCA layer rejects the key or
   *     algorithm
   */
  byte[] sign(byte[] data, PrivateKey privateKey);

  /**
   * Verifies a signature over the given data.
   *
   * @param data the signature base bytes
   * @param signature the signature to check
   * @param publicKey the verification key
   * @return {@code true} if the signature is valid, {@code false} if it does
   *     not match
   * @throws SignatureOperationException if the JCA layer rejects the key or
   *     algorithm (a structurally invalid signature returns {@code false},
   *     not an exception)
   */
  boolean verify(byte[] data, byte[] signature, PublicKey publicKey);
}
