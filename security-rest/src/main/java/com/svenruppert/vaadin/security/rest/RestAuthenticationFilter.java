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

/**
 * Authenticated-only REST filter for endpoints that require any subject but
 * no specific permission.
 * <p>
 * Returns {@code 401} with body {@code Unauthorized} when no subject is
 * resolved; delegates to the handler otherwise. Generic and side-effect-free.
 */
public final class RestAuthenticationFilter {

  private final RestSubjectResolver subjectResolver;

  public RestAuthenticationFilter(RestSubjectResolver subjectResolver) {
    this.subjectResolver = subjectResolver;
  }

  public void requireAuthenticated(RestRequest request, RestResponse response, RestHandler handler) {
    if (subjectResolver.resolveSubject(request).isEmpty()) {
      response.status(401);
      response.body("Unauthorized");
      return;
    }
    handler.handle(request, response);
  }
}
