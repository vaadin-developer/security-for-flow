package eu.jsentinel.jcustos.events.keys;

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
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithm;

import java.security.PrivateKey;

/**
 * Signer-side key SPI (Konzept §575): supplies the current private key and the
 * algorithm the publish pipeline uses to sign envelopes.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public interface JCustosEventSigningKeyProvider {

  /**
   * @return the id of the current signing key, stamped onto the envelope so a
   *     consumer can resolve the matching verification key
   */
  KeyId currentKeyId();

  /**
   * @return the current private signing key
   */
  PrivateKey currentSigningKey();

  /**
   * @return the signature algorithm bound to the current key
   */
  SignatureAlgorithm currentAlgorithm();

  /**
   * Captures the current signing key as one self-consistent snapshot — key id,
   * algorithm and private key belonging to the same key generation. The publish
   * pipeline calls this exactly once per publish and uses the snapshot for both
   * the envelope's {@code keyId} stamp and the signing operation (R00).
   *
   * <p>The {@code default} implementation is <strong>not</strong> atomic: it
   * composes {@link #currentKeyId()}, {@link #currentAlgorithm()} and
   * {@link #currentSigningKey()} as three separate reads. A provider whose
   * current key can change concurrently (rotation) <strong>must</strong>
   * override this method to build the snapshot from one consistent internal
   * read; immutable providers can rely on the default.
   *
   * @return a self-consistent snapshot of the current signing key
   * @since 00.80.00
   */
  default SigningKeySnapshot signingSnapshot() {
    return new SigningKeySnapshot(currentKeyId(), currentAlgorithm(), currentSigningKey());
  }
}
