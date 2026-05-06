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
package com.svenruppert.vaadin.security.demo.app.views.workspaces;

import com.svenruppert.vaadin.security.demo.app.views.components.PermissionDemoCard;
import com.svenruppert.vaadin.security.demo.app.views.components.ViewNavigationCard;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;

public class DemoUselessWorkspace extends Composite<Div> {

  public DemoUselessWorkspace() {
    Span badge = new Span("DEMO");
    badge.getElement().getThemeList().add("badge primary");

    H2 heading = new H2("Playground");

    HorizontalLayout header = new HorizontalLayout(VaadinIcon.FLASK.create(), heading);
    header.setAlignItems(FlexComponent.Alignment.CENTER);
    header.setSpacing(true);

    Paragraph description = new Paragraph(
        "Experimental sandbox. This tab demonstrates the "
        + "isCurrentUserAuthorizedFor(null) check — it is always visible because "
        + "a null role list is treated as 'no restriction'.");

    VerticalLayout content = new VerticalLayout(
        badge, header, description,
        new PermissionDemoCard(),
        new ViewNavigationCard());
    content.addClassNames("workspace", "workspace-demo");
    content.setSpacing(false);
    content.getThemeList().add("spacing-s");

    getContent().add(content);
  }
}
