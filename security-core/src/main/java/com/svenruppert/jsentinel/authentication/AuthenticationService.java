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
package com.svenruppert.jsentinel.authentication;

/**
 * SPI contract for credential validation and subject loading.
 * <p>
 * Implementations must be registered in
 * {@code META-INF/services/com.svenruppert.jsentinel.authentication.AuthenticationService}.
 *
 * @param <T> the credentials type (e.g. a username/password record)
 * @param <U> the subject (user) type
 */
public interface AuthenticationService<T, U> {

  /**
   * Validates the given credentials.
   *
   * @param credentials the credentials to check
   * @return {@code true} if the credentials are valid
   */
  boolean checkCredentials(T credentials);

  /**
   * Loads the subject for the given (already validated) credentials.
   *
   * @param credentials the validated credentials
   * @return the authenticated subject
   */
  U loadSubject(T credentials);

  /**
   * Returns the class token for the subject type.
   * Used by {@link com.svenruppert.jsentinel.authorization.api.SubjectStore}
   * implementations to store and retrieve the subject.
   *
   * @return the subject class
   */
  Class<U> subjectType();

}
