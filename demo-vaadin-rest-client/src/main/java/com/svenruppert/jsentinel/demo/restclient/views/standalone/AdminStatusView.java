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
package com.svenruppert.jsentinel.demo.restclient.views.standalone;

import com.svenruppert.jsentinel.authorization.annotations.RequiresRole;
import com.svenruppert.jsentinel.demo.restclient.views.components.BackendOperationCard;
import com.svenruppert.jsentinel.demo.restclient.views.components.PermissionDemoCard;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;

/** Stil A2 — generic role annotation from {@code security-core}. */
@Route(AdminStatusView.NAV)
@RequiresRole("ROLE_ADMIN")
public class AdminStatusView extends Composite<Div> {

  public static final String NAV = "admin";

  public AdminStatusView() {
    H1 h = new H1("Admin status (Stil A2 — @RequiresRole)");
    Paragraph p = new Paragraph(
        "View-level guard via @RequiresRole(\"ROLE_ADMIN\"). Editor and "
            + "Viewer get rerouted; Admin reaches the view and can call "
            + "the admin-only backend operation below.");
    getContent().add(new VerticalLayout(h, p, new BackendOperationCard(), new PermissionDemoCard()));
  }
}
