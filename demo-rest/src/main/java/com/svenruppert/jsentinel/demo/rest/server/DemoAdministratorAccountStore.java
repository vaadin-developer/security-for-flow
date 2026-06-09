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
package com.svenruppert.jsentinel.demo.rest.server;

import com.svenruppert.jsentinel.bootstrap.AdministratorAccountStore;
import com.svenruppert.jsentinel.bootstrap.NewAdministrator;
import com.svenruppert.jsentinel.demo.rest.domain.DemoRole;
import com.svenruppert.jsentinel.demo.rest.domain.DemoUser;
import com.svenruppert.jsentinel.demo.rest.domain.DemoUserStore;

/**
 * Adapter that lets the bootstrap library create the first administrator
 * inside the demo {@link DemoUserStore}.
 */
public final class DemoAdministratorAccountStore implements AdministratorAccountStore {

  private final DemoUserStore users;

  public DemoAdministratorAccountStore(DemoUserStore users) {
    this.users = users;
  }

  @Override
  public boolean hasAnyAdministrator() {
    return users.hasAnyAdministrator();
  }

  @Override
  public void createAdministrator(NewAdministrator newAdministrator) {
    String displayName = newAdministrator.displayName() == null || newAdministrator.displayName().isBlank()
        ? newAdministrator.username()
        : newAdministrator.displayName();
    users.register(new DemoUser(
        newAdministrator.username(),
        displayName,
        newAdministrator.passwordHash(),
        DemoRole.ROLE_ADMIN));
  }
}
