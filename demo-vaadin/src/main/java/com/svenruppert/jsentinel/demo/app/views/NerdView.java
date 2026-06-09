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
package com.svenruppert.jsentinel.demo.app.views;

import com.svenruppert.jsentinel.demo.app.security.roles.AuthorizationRole;
import com.svenruppert.jsentinel.demo.app.security.roles.VisibleFor;
import com.svenruppert.jsentinel.demo.app.views.components.PermissionDemoCard;
import com.svenruppert.jsentinel.demo.app.views.components.ViewNavigationCard;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;

@Route(NerdView.NAV)
@VisibleFor({AuthorizationRole.ADMIN, AuthorizationRole.NERD})
public class NerdView extends Composite<Div> {

  public static final String NAV = "nerd";

  public NerdView() {
    HorizontalLayout badges = new HorizontalLayout();
    Span adminBadge = new Span("ADMIN");
    adminBadge.getElement().getThemeList().add("badge error");
    Span nerdBadge = new Span("NERD");
    nerdBadge.getElement().getThemeList().add("badge contrast");
    badges.add(adminBadge, nerdBadge);

    H1 heading = new H1("Nerd standalone view");

    Paragraph description = new Paragraph(
        "Standalone route protected at view level by "
            + "@VisibleFor({ADMIN, NERD}). USER and NOBODY get redirected. "
            + "The permission demo below shows that even on this view the "
            + "individual buttons follow the user's permissions.");

    Button back = new Button("Back to home", VaadinIcon.HOME.create(),
        e -> UI.getCurrent().navigate(MainView.class));
    back.addThemeVariants(ButtonVariant.LUMO_TERTIARY);

    VerticalLayout layout = new VerticalLayout(
        new HorizontalLayout(badges, heading),
        description,
        new PermissionDemoCard(),
        new ViewNavigationCard(),
        back);
    layout.setSpacing(false);
    layout.getThemeList().add("spacing-s");
    layout.addClassNames("workspace", "workspace-nerd");

    getContent().add(layout);
  }
}
