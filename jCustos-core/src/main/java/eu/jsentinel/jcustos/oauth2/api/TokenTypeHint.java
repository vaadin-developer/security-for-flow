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
package eu.jsentinel.jcustos.oauth2.api;

/**
 * The {@code token_type_hint} for introspection / revocation (RFC 7009 §2.1,
 * RFC 7662 §2.1, V00.77).
 *
 * @since 00.77.00
 */
public enum TokenTypeHint {
  ACCESS_TOKEN("access_token"),
  REFRESH_TOKEN("refresh_token");

  private final String wire;

  TokenTypeHint(String wire) {
    this.wire = wire;
  }

  /** @return the {@code token_type_hint} wire value. */
  public String wire() {
    return wire;
  }
}
