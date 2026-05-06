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
package com.svenruppert.vaadin.security.demo.app.views.components;

import com.svenruppert.vaadin.security.demo.app.views.AdminView;
import com.svenruppert.vaadin.security.demo.app.views.NerdView;
import com.svenruppert.vaadin.security.demo.app.views.PublicView;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.H3;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.RouterLink;

/**
 * Card with router links to the three standalone demo views. Demonstrates
 * view-level security: the link is rendered for everyone, but navigation is
 * blocked by {@code AuthorizationListener} for users without the matching
 * role. The user sees the framework reroute kick in.
 */
public class ViewNavigationCard extends Composite<VerticalLayout> {

  public ViewNavigationCard() {
    VerticalLayout root = getContent();
    root.addClassName("view-navigation-card");
    root.setSpacing(false);
    root.getThemeList().add("spacing-s");

    root.add(new H3("Standalone views (view-level security)"));
    root.add(new Paragraph(
        "These links navigate to standalone routes. The links are visible "
            + "to everyone, but navigation is blocked by the framework's "
            + "AuthorizationListener for users without the required role. "
            + "Try opening them after logging in as different demo users."));

    HorizontalLayout links = new HorizontalLayout();
    links.setSpacing(true);
    links.add(new RouterLink("/admin (ADMIN)", AdminView.class));
    links.add(new RouterLink("/nerd (ADMIN, NERD)", NerdView.class));
    links.add(new RouterLink("/public (open)", PublicView.class));
    root.add(links);
  }
}
