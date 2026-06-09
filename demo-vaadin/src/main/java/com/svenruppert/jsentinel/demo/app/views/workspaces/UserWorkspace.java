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
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;

public class UserWorkspace extends Composite<Div> {

  public UserWorkspace() {
    Span badge = new Span("USER");
    badge.getElement().getThemeList().add("badge success");

    H2 heading = new H2("My Area");

    HorizontalLayout header = new HorizontalLayout(VaadinIcon.USER.create(), heading);
    header.setAlignItems(FlexComponent.Alignment.CENTER);
    header.setSpacing(true);

    Paragraph description = new Paragraph(
        "Your personal workspace. View your profile, preferences, and activity. "
        + "All authenticated users have access to this section.");

    VerticalLayout content = new VerticalLayout(
        badge, header, description,
        new PermissionDemoCard(),
        new ViewNavigationCard());
    content.addClassNames("workspace", "workspace-user");
    content.setSpacing(false);
    content.getThemeList().add("spacing-s");

    getContent().add(content);
  }
}
