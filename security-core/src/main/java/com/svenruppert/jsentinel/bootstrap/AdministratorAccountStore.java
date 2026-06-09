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
package com.svenruppert.jsentinel.bootstrap;

/**
 * Application-side seam used by {@link InitialAdminBootstrapService} to
 * answer "is anyone an administrator?" and to persist the freshly created
 * initial administrator. The library does not own the user model — the
 * consuming application supplies it.
 */
public interface AdministratorAccountStore {

  /**
   * Returns {@code true} when at least one active administrator account
   * exists. The bootstrap mechanism stops being available as soon as this
   * returns {@code true}.
   */
  boolean hasAnyAdministrator();

  /**
   * Persists the freshly created initial administrator. Implementations
   * must store {@link NewAdministrator#passwordHash()} as-is — no
   * further hashing.
   *
   * @param newAdministrator the administrator account to persist
   * @throws RuntimeException if the username already exists or the
   *                          underlying store fails
   */
  void createAdministrator(NewAdministrator newAdministrator);
}
