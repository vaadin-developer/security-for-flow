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
package com.svenruppert.vaadin.security.demo.restclient.security;

import com.svenruppert.vaadin.security.authorization.LoginListener;
import com.svenruppert.vaadin.security.authorization.LoginView;
import com.svenruppert.vaadin.security.autoservice.api.SecurityAutoService;
import com.svenruppert.vaadin.security.demo.restclient.backend.RemoteUser;
import com.svenruppert.vaadin.security.demo.restclient.views.MainView;
import com.svenruppert.vaadin.security.demo.restclient.views.MyLoginView;
import com.vaadin.flow.component.Component;

/**
 * SPI-loaded {@link LoginListener} for the {@link RemoteUser} subject type.
 */
@SecurityAutoService(LoginListener.class)
public class BackedLoginListener extends LoginListener<RemoteUser> {

  @Override
  public Class<? extends LoginView> loginNavigationTarget() {
    return MyLoginView.class;
  }

  @Override
  public Class<? extends Component> defaultNavigationTarget() {
    return MainView.class;
  }

  @Override
  public void notARestrictedTarget(Class<?> navigationTarget) {
    // No-op: the framework already calls beforeEnter for every navigation;
    // unrestricted targets simply pass through.
  }
}
