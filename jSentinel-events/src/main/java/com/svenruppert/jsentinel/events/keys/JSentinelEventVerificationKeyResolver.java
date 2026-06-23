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

import java.security.PublicKey;
import java.util.Optional;

/**
 * Verifier-side key SPI (Konzept §583): resolves a public key and its status
 * for a given {@link KeyId}, so the consume pipeline can verify a signature
 * and reject envelopes signed under an unknown or revoked key.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public interface JSentinelEventVerificationKeyResolver {

  /**
   * @param keyId the key referenced by the envelope
   * @return the public key, if one is known for the id
   */
  Optional<PublicKey> resolveVerificationKey(KeyId keyId);

  /**
   * @param keyId the key referenced by the envelope
   * @return the lifecycle status; {@link KeyStatus#UNKNOWN} if no key is known
   */
  KeyStatus keyStatus(KeyId keyId);
}
