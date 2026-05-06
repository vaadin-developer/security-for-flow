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
package com.svenruppert.vaadin.security.demo.app.security.bootstrap;

import com.svenruppert.vaadin.security.bootstrap.AdministratorAccountStore;
import com.svenruppert.vaadin.security.bootstrap.NewAdministrator;
import com.svenruppert.vaadin.security.demo.app.security.model.DemoUserDirectory;
import com.svenruppert.vaadin.security.demo.app.security.model.MyUser;
import com.svenruppert.vaadin.security.demo.app.security.roles.AuthorizationRole;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Adapter that exposes a {@link DemoUserDirectory} to the bootstrap
 * library.
 */
public final class VaadinAdministratorAccountStore implements AdministratorAccountStore {

  private final DemoUserDirectory directory;
  private final AtomicLong idSequence = new AtomicLong(1000);

  public VaadinAdministratorAccountStore(DemoUserDirectory directory) {
    this.directory = Objects.requireNonNull(directory, "directory");
  }

  @Override
  public boolean hasAnyAdministrator() {
    return directory.hasAnyAdministrator();
  }

  @Override
  public void createAdministrator(NewAdministrator newAdministrator) {
    Set<AuthorizationRole> roles = new HashSet<>();
    roles.add(AuthorizationRole.ADMIN);
    roles.add(AuthorizationRole.USER);
    String displayName = newAdministrator.displayName() == null || newAdministrator.displayName().isBlank()
        ? newAdministrator.username()
        : newAdministrator.displayName();
    MyUser user = new MyUser(idSequence.getAndIncrement(), displayName, roles);
    directory.registerWithHashedPassword(newAdministrator.username(), newAdministrator.passwordHash(), user);
  }
}
