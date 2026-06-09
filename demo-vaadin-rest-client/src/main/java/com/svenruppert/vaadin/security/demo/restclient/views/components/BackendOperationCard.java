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
package com.svenruppert.vaadin.security.demo.restclient.views.components;

import com.svenruppert.vaadin.security.demo.restclient.backend.BackendClientProvider;
import com.svenruppert.vaadin.security.demo.restclient.backend.BackendException;
import com.svenruppert.vaadin.security.demo.restclient.backend.RemoteAdminStatus;
import com.svenruppert.vaadin.security.demo.restclient.backend.RemoteDocument;
import com.svenruppert.vaadin.security.demo.restclient.security.ClientJSentinelContext;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.html.H4;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationVariant;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;

import java.util.List;

/**
 * Buttons that hit the actual REST backend. Visibility is decided locally
 * (UX hint), but the click always calls the server — the {@code 403} or
 * the {@code 200} comes from there. Demonstrates that even if the UI
 * shows the button (e.g. by intent or by mistake), the backend remains
 * the security boundary.
 */
public class BackendOperationCard extends Composite<VerticalLayout> {

  public BackendOperationCard() {
    VerticalLayout root = getContent();
    root.setSpacing(false);
    root.getThemeList().add("spacing-s");

    root.add(new H4("Backend operations (real REST round-trips)"));
    root.add(new Paragraph(
        "Click any button — the demo calls the backend with the current "
            + "session token. Permission decisions happen on the server. "
            + "Try with viewer / editor / admin to see 200 / 403 vary."));

    HorizontalLayout row = new HorizontalLayout();
    row.add(button("List documents", this::listDocuments));
    row.add(button("Create document", this::createDocument));
    row.add(button("Delete document #1", () -> deleteDocument(1)));
    row.add(button("Admin status", this::adminStatus));
    root.add(row);
  }

  private static Button button(String label, Runnable action) {
    Button b = new Button(label, e -> action.run());
    b.addThemeVariants(ButtonVariant.LUMO_TERTIARY, ButtonVariant.LUMO_SMALL);
    return b;
  }

  private void listDocuments() {
    runWithToken(token -> {
      List<RemoteDocument> docs = BackendClientProvider.client().listDocuments(token);
      ok("Backend returned " + docs.size() + " document(s)");
    });
  }

  private void createDocument() {
    runWithToken(token -> {
      RemoteDocument doc = BackendClientProvider.client()
          .createDocument(token, "demo-" + System.currentTimeMillis());
      ok("Created #" + doc.id() + " '" + doc.title() + "'");
    });
  }

  private void deleteDocument(long id) {
    runWithToken(token -> {
      BackendClientProvider.client().deleteDocument(token, id);
      ok("Deleted #" + id);
    });
  }

  private void adminStatus() {
    runWithToken(token -> {
      RemoteAdminStatus status = BackendClientProvider.client().adminStatus(token);
      ok("Admin status: " + status.status());
    });
  }

  private static void runWithToken(java.util.function.Consumer<String> action) {
    String token = ClientJSentinelContext.token().orElse(null);
    if (token == null) {
      err("No active session — log in again");
      return;
    }
    try {
      action.accept(token);
    } catch (BackendException ex) {
      switch (ex.kind()) {
        case Forbidden       -> err("403 — backend denied: missing permission");
        case Unauthenticated -> err("401 — session expired, please log in");
        case NotFound        -> err("404 — resource not found");
        case BadRequest      -> err("400 — bad request");
        case Conflict        -> err("409 — conflict");
        case ServerError     -> err("500 — backend internal error");
        case Transport       -> err("Transport error: " + ex.getMessage());
        default              -> err("Unexpected backend response");
      }
    }
  }

  private static void ok(String msg) {
    Notification n = Notification.show(msg, 2500, Notification.Position.BOTTOM_END);
    n.addThemeVariants(NotificationVariant.LUMO_SUCCESS);
  }

  private static void err(String msg) {
    Notification n = Notification.show(msg, 3500, Notification.Position.BOTTOM_END);
    n.addThemeVariants(NotificationVariant.LUMO_ERROR);
  }
}