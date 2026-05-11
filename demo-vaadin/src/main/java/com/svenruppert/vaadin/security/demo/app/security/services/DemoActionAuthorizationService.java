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
package com.svenruppert.vaadin.security.demo.app.security.services;

import com.svenruppert.vaadin.security.action.ActionAuthorizationService;
import com.svenruppert.vaadin.security.action.ActionPermission;
import com.svenruppert.vaadin.security.action.StaticActionAuthorizationService;
import com.svenruppert.vaadin.security.demo.app.security.model.MyUser;

/**
 * SPI-registered {@code ActionAuthorizationService<MyUser>}. Backs
 * {@link com.svenruppert.vaadin.security.demo.app.views.components.PermissionDemoCard}.
 * Delegates to the core default that checks each
 * {@link ActionPermission} against the
 * subject's permission set via {@code AuthorizationService.permissionsFor(...)}
 * — same string vocabulary as {@code DemoPermission}.
 */
public final class DemoActionAuthorizationService
    implements ActionAuthorizationService<MyUser> {

  private final StaticActionAuthorizationService<MyUser> delegate =
      new StaticActionAuthorizationService<>(MyUser.class);

  @Override
  public boolean isAllowed(MyUser subject, ActionPermission permission) {
    return delegate.isAllowed(subject, permission);
  }

  @Override
  public void requireAllowed(MyUser subject, ActionPermission permission) {
    delegate.requireAllowed(subject, permission);
  }
}
