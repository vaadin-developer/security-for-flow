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
package com.svenruppert.jsentinel.authorization.impl;

import com.svenruppert.jsentinel.authentication.AuthenticationService;

/**
 * Test-scope SPI {@link AuthenticationService}. Registered via
 * {@code META-INF/services} for tests in this module — never used in
 * production. Treats the credentials and the loaded subject as a single
 * {@link String} so tests can compose user data without any extra type.
 */
public final class StubAuthenticationService implements AuthenticationService<String, String> {

  @Override
  public boolean checkCredentials(String credentials) {
    return credentials != null && !credentials.isBlank();
  }

  @Override
  public String loadSubject(String credentials) {
    return credentials;
  }

  @Override
  public Class<String> subjectType() {
    return String.class;
  }
}
