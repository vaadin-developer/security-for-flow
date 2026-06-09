/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
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
package com.svenruppert.jsentinel.credential.password.pepper;

import java.util.Optional;

/**
 * Resolves the pepper material associated with a stored pepper key id.
 *
 * <p>Phase 1a only ships {@link NoOpPepperService}; the real
 * HMAC-backed pepper service arrives with Prompt 017
 * (<em>Real Pepper Service and post-KDF HMAC</em>). Until then this
 * interface exists so the verification pipeline can stay forward
 * compatible without ever pretending to offer pepper protection.</p>
 */
public interface PepperService {

  /**
   * Currently active pepper key id used by the policy when producing
   * new hashes. {@link Optional#empty()} signals that no pepper is
   * applied to new hashes.
   */
  Optional<String> activeKeyId();

  /**
   * Resolves the pepper material for a previously stored hash.
   *
   * @return the pepper bytes, or {@link Optional#empty()} when no
   *         pepper service knows about this key id
   */
  Optional<byte[]> resolve(String keyId);
}
