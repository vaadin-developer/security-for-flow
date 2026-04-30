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
package com.svenruppert.vaadin.security.demo.app.security;

import com.vaadin.flow.component.Component;
import com.svenruppert.vaadin.security.demo.app.security.model.MyUser;
import com.svenruppert.vaadin.security.demo.app.security.roles.VisibleFor;
import com.svenruppert.vaadin.security.demo.app.views.MainView;
import com.svenruppert.vaadin.security.demo.app.views.MyLoginView;
import com.svenruppert.vaadin.security.authorization.LoginListener;
import com.svenruppert.vaadin.security.authorization.LoginView;

public class MyLoginListener
    extends LoginListener<MyUser> {

  public void notARestrictedTarget(Class<?> navigationTarget) {
    logger().info("NavigationTarget is not a restricted View - no login required {}", navigationTarget.getSimpleName());
  }

  public Class<VisibleFor> restrictionAnnotation() {
    return VisibleFor.class;
  }

  public Class<? extends LoginView> loginNavigationTarget() {
    return MyLoginView.class;
  }

  public Class<? extends Component> defaultNavigationTarget() {
    return MainView.class;
  }

}
