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
package com.svenruppert.jsentinel.rest;

/**
 * Minimal framework-independent REST response abstraction.
 */
public interface RestResponse {

  /**
   * Sets the response status.
   *
   * @param statusCode HTTP status code
   */
  void status(int statusCode);

  /**
   * Sets the response body.
   *
   * @param body response body
   */
  void body(String body);

  /**
   * Sets a response header.
   * <p>
   * Default is a safe no-op so existing implementations keep working
   * even before they opt in. Implementations should override this to
   * actually emit the header.
   *
   * @param name  header name; non-{@code null}, non-blank
   * @param value header value; non-{@code null}
   */
  default void header(String name, String value) {
    // implementations that don't yet support headers fall through silently
  }
}
