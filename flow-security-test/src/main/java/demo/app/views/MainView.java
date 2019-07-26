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
package demo.app.views;


import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.applayout.AppLayout;
import com.vaadin.flow.component.applayout.DrawerToggle;
import com.vaadin.flow.component.html.Image;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.tabs.Tab;
import com.vaadin.flow.component.tabs.Tabs;
import com.vaadin.flow.router.Route;
import demo.app.security.roles.VisibleFor;
import demo.app.views.workspaces.*;
import org.jetbrains.annotations.NotNull;
import org.rapidpm.dependencies.core.logger.HasLogger;

import java.util.HashMap;
import java.util.Map;

import static demo.app.MySessionAccessor.isCurrentUserAuthorizedFor;
import static demo.app.security.roles.AuthorizationRole.*;

@Route(MainView.NAV)
@VisibleFor(USER) //TODO indirect assumption
public class MainView
    extends AppLayout
    implements HasLogger {

  public static final String NAV = "";

  public MainView() {

    addToNavbar(new DrawerToggle(),
                //TODO resource AS Stream thing... //resources/logo.png
                new Image("https://i.imgur.com/GPpnszs.png", "Vaadin Logo") {{
                  setHeight("44px");
                }});
    addToDrawer(createMainMenu());
    setContent(new Span("start working.."));
  }

  //maybe tab to Supplier<Compnent>
  private Map<Tab, Component> tab2Workspace = new HashMap<>();

  @NotNull
  private Tabs createMainMenu() {
    final Tabs tabs = new Tabs();
    tabs.setOrientation(Tabs.Orientation.VERTICAL);
    if (isCurrentUserAuthorizedFor(ADMIN)) tabs.add(adminTab());
    if (isCurrentUserAuthorizedFor(ADMIN, NERD)) tabs.add(nerdTab());
    if (isCurrentUserAuthorizedFor(USER)) tabs.add(userTab());
    tabs.add(publicAllTab());
    //For demo only
    if (isCurrentUserAuthorizedFor(null)) tabs.add(demoUselessTab());

    tabs.addSelectedChangeListener(event -> {
      final Tab selectedTab = event.getSelectedTab();
      final Component component = tab2Workspace.get(selectedTab);
      setContent(component);
    });

    return tabs;
  }

  @NotNull
  private Tab demoUselessTab() {
    final Tab tab = new Tab("DemoUselessTab");
    tab2Workspace.put(tab, new DemoUselessWorkspace());
    return tab;
  }

  @NotNull
  private Tab publicAllTab() {
    final Tab tab = new Tab("PublicAllTab");
    tab2Workspace.put(tab, new PublicAllWorkspace());
    return tab;
  }

  @NotNull
  private Tab userTab() {
    final Tab tab = new Tab("UserTab");
    tab2Workspace.put(tab, new UserWorkspace());
    return tab;
  }

  @NotNull
  private Tab nerdTab() {
    final Tab tab = new Tab("NerdTab");
    tab2Workspace.put(tab, new NerdWorkspace());
    return tab;
  }

  @NotNull
  private Tab adminTab() {
    final Tab tab = new Tab("AdminTab");

    tab2Workspace.put(tab, new AdminWorkspace());
    return tab;
  }

  //For Reusable Components
//  @VisibleFor(ADMIN)
//  public static final class AdminTab implements Supplier<Tab> {
//    @Override
//    public Tab get() {
//      return new Tab("AdminTab");
//    }
//  }
//    duplicated code - see impl of RoleBasedAccessEvaluator
//    Stream.of(new AdminTab())
//      .filter(s -> {
//    final Class<? extends AdminTab> aClass = s.getClass();
//    final boolean isRestricted = aClass.isAnnotationPresent(VisibleFor.class);
//    if (isRestricted) {
//      final AuthorizationRole subjectRole = MySessionAccessor.currentSubject().role();
//      final VisibleFor visibleFor = aClass.getAnnotation(VisibleFor.class);
//      final AuthorizationRole[] authorizationRoles = visibleFor.value();
//      return Arrays.asList(authorizationRoles).contains(subjectRole);
//    } else {
//      return true;
//    }
//    })
//      .map(Supplier::get)
//      .forEachOrdered(tabs::add);

  //For factory-template-classes
//  @NotNull
//  @VisibleFor(ADMIN)
//  private Tab adminTab() {
//    return new Tab("AdminTab");
//  }
//
//  @NotNull
//  @VisibleFor({ADMIN , NERD})
//  private Tab nerdTab() {
//    return new Tab("NerdTab");
//  }
}
