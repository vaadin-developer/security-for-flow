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

/**
 * Shared size ceilings for JOSE compact-serialization inputs (CWE-770).
 *
 * <p>JS-SEC-053: the JWE decoder capped its input at 100 KB but the JWS validator processed an
 * unbounded compact token (base64-decoding the header + parsing before any key/allow-list check).
 * This holds the single shared ceiling so every JOSE compact parser — {@code NimbusJwtValidator},
 * {@code NimbusJweDecoder}, {@code JweUnwrappingJwtValidator} — bounds its input consistently. A
 * signed/encrypted JWT is at most a few tens of KB; 100 KB sits far above any legitimate token.
 *
 * @since 00.79.41
 */
final class JoseLimits {

  /** Maximum accepted length of a JOSE compact serialization (JWS or JWE). */
  static final int MAX_COMPACT_BYTES = 100_000;

  private JoseLimits() {
  }
}
