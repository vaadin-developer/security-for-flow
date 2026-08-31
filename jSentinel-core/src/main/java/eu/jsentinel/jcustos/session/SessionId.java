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
package eu.jsentinel.jcustos.session;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

/**
 * Strongly-typed identifier of an authenticated session.
 * <p>
 * Used as the primary key of {@link SessionStore}. The
 * {@code value} component is intentionally a free-form
 * {@code String} so adapters can supply whatever shape their session
 * mechanism produces (Vaadin's session id, an opaque token, a JWT id);
 * the record only guarantees non-blank.
 *
 * @param value non-blank session identifier
 */
@ExperimentalJCustosApi
public record SessionId(String value) {

  /**
   * Validates the record component.
   *
   * @param value non-blank session identifier
   */
  public SessionId {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("value must not be blank");
    }
  }

  /**
   * Factory mirror of the canonical constructor.
   *
   * @param value non-blank session identifier
   * @return new {@code SessionId}
   */
  public static SessionId of(String value) {
    return new SessionId(value);
  }
}
