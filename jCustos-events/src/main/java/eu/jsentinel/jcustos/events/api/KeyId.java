package eu.jsentinel.jcustos.events.api;

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

/**
 * Reference to the key pair used to sign / verify an envelope (Konzept §340).
 * Maps to a KeyStore alias or explicit key metadata in the key-management
 * layer and supports rotation without an API break.
 *
 * @param value non-blank key identifier
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public record KeyId(String value) {

  public KeyId {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("KeyId value must not be null or blank");
    }
  }

  public static KeyId of(String value) {
    return new KeyId(value);
  }
}
