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
package com.svenruppert.vaadin.security.rest;

import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import com.svenruppert.vaadin.security.session.SessionMetadata;

import java.util.Optional;

/**
 * Resolves the current security subject from a REST request.
 */
@FunctionalInterface
public interface RestSubjectResolver {

  /**
   * Resolves the current subject.
   *
   * @param request request
   * @return subject, or empty if no subject is authenticated
   */
  Optional<SecuritySubject> resolveSubject(RestRequest request);

  /**
   * Resolves session metadata for the current request.
   * <p>
   * The default returns {@link Optional#empty()} so existing
   * implementations keep working. Implementations that want the
   * REST filters to enforce idle / absolute lifetime via
   * {@code SessionPolicy.evaluate(SessionMetadata)} should override
   * this and return a populated record built from their token
   * store's metadata (creation timestamp, last-activity timestamp).
   *
   * @param request request
   * @return metadata for the current request, or empty when the
   *         resolver doesn't track session lifetime
   */
  default Optional<SessionMetadata> resolveSessionMetadata(RestRequest request) {
    return Optional.empty();
  }
}
