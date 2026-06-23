package com.svenruppert.jsentinel.events.keys;

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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.api.KeyId;
import com.svenruppert.jsentinel.events.signature.SignatureAlgorithm;

import java.security.PrivateKey;

/**
 * Signer-side key SPI (Konzept §575): supplies the current private key and the
 * algorithm the publish pipeline uses to sign envelopes.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public interface JSentinelEventSigningKeyProvider {

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
}
