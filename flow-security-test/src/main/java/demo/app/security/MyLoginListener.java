/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package demo.app.security;

import com.vaadin.flow.component.Component;
import demo.app.security.model.MyUser;
import demo.app.security.roles.VisibleFor;
import demo.app.views.MainView;
import demo.app.views.MyLoginView;
import org.jetbrains.annotations.NotNull;
import org.rapidpm.vaadin.security.authorization.LoginListener;
import org.rapidpm.vaadin.security.authorization.LoginView;

public class MyLoginListener
    extends LoginListener<MyUser> {

  public void notARestrictedTarget(Class<?> navigationTarget) {
    logger().info("NavigationTarget is not a restricted View - no login required " + navigationTarget.getSimpleName());
  }

  @NotNull
  public Class<VisibleFor> restrictionAnnotation() {
    return VisibleFor.class;
  }

  @NotNull
  public Class<? extends LoginView> loginNavigationTarget() {
    return MyLoginView.class;
  }

  @NotNull
  public Class<? extends Component> defaultNavigationTarget() {
    return MainView.class;
  }

}
