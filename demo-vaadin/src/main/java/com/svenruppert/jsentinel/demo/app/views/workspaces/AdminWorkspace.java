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
package com.svenruppert.jsentinel.demo.app.views.workspaces;

import com.svenruppert.jsentinel.demo.app.views.components.PermissionDemoCard;
import com.svenruppert.jsentinel.demo.app.views.components.ViewNavigationCard;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;

public class AdminWorkspace extends Composite<Div> {

  public AdminWorkspace() {
    Span badge = new Span("ADMIN");
    badge.getElement().getThemeList().add("badge error");

    H2 heading = new H2("Admin Console");

    HorizontalLayout header = new HorizontalLayout(VaadinIcon.COG.create(), heading);
    header.setAlignItems(com.vaadin.flow.component.orderedlayout.FlexComponent.Alignment.CENTER);
    header.setSpacing(true);

    Paragraph description = new Paragraph(
        "Full system control. Manage users, assign roles, and configure security policies. "
        + "Access to this section is restricted to users with the ADMIN role.");

    VerticalLayout content = new VerticalLayout(
        badge, header, description,
        new PermissionDemoCard(),
        new ViewNavigationCard());
    content.addClassNames("workspace", "workspace-admin");
    content.setSpacing(false);
    content.getThemeList().add("spacing-s");

    getContent().add(content);
  }
}
