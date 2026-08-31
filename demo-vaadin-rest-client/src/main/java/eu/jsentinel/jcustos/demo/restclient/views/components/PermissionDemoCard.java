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
package eu.jsentinel.jcustos.demo.restclient.views.components;

import eu.jsentinel.jcustos.authorization.api.AccessDeniedException;
import eu.jsentinel.jcustos.authorization.api.PermissionGuard;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.demo.restclient.security.ClientJSentinelContext;
import eu.jsentinel.jcustos.demo.restclient.security.DemoPolicyInitListener;
import eu.jsentinel.jcustos.starter.ui.SecuredUi;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.details.Details;
import com.vaadin.flow.component.html.H4;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationVariant;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;

/**
 * Pattern A vs Pattern B for the cached {@link eu.jsentinel.jcustos.demo.restclient.backend.RemoteUser}
 * snapshot — purely a UX device. Mutating actions still go through
 * {@link BackendOperationCard} so the server has the final word.
 */
public class PermissionDemoCard extends Composite<VerticalLayout> {

  private static final PermissionName DOC_READ = new PermissionName("document:read");
  private static final PermissionName DOC_CREATE = new PermissionName("document:create");
  private static final PermissionName DOC_DELETE = new PermissionName("document:delete");
  private static final PermissionName ADMIN_ACCESS = new PermissionName("admin:access");

  public PermissionDemoCard() {
    VerticalLayout root = getContent();
    root.setSpacing(false);
    root.getThemeList().add("spacing-s");

    root.add(new H4("Pattern A — UX adaptation (visible only when allowed)"));
    root.add(new Paragraph(
        "Buttons are added to the layout only if the cached RemoteUser "
            + "snapshot carries the required permission. Hiding UI is a UX "
            + "hint, not a security boundary."));
    root.add(visibilityRow());

    root.add(new H4("Pattern B — Local guard (always visible, throws on click)"));
    root.add(new Paragraph(
        "Buttons are always visible. On click the demo calls "
            + "PermissionGuard.requirePermission(...) against the cached "
            + "snapshot. The mutating action that follows would *also* go "
            + "to the backend (see BackendOperationCard), where the server "
            + "is authoritative."));
    root.add(enforcementRow());

    root.add(new H4("Pattern C — V00.72 SecuredUi.button (max comfort)"));
    root.add(new Paragraph(
        "Buttons assembled through the starter's SecuredUi.button(...) "
            + "fluent builder — no PermissionGuard call, no manual "
            + "isAllowed plumbing. The visibility wiring reads the current "
            + "subject from the V00.73 VaadinSessionSubjectStore that "
            + "BackedLoginListener populates on login. The trailing button "
            + "uses .requiresPolicy(\"documents.editor-or-admin\") to "
            + "evaluate the policy registered in DemoPolicyInitListener."));
    root.add(securedUiButtonRow());

    root.add(new H4("Pattern D — V00.74 SecuredUi.component (any Vaadin component)"));
    root.add(new Paragraph(
        "SecuredUi.button / link / menuItem cover the three classic "
            + "secured surfaces, but the V00.74 SecuredUi.component(...) "
            + "generic builder secures any Vaadin component — FormLayout, "
            + "Details, Dialog, Tab. The Details block below is only "
            + "visible to subjects holding admin:access."));
    root.add(buildAdminDetailsBlock());
  }

  private static HorizontalLayout visibilityRow() {
    HorizontalLayout row = new HorizontalLayout();
    addIfAllowed(row, DOC_READ, "Read");
    addIfAllowed(row, DOC_CREATE, "Create");
    addIfAllowed(row, DOC_DELETE, "Delete");
    addIfAllowed(row, ADMIN_ACCESS, "Admin");
    if (row.getComponentCount() == 0) {
      row.add(new Span("(No backend permissions for this user.)"));
    }
    return row;
  }

  private static HorizontalLayout enforcementRow() {
    HorizontalLayout row = new HorizontalLayout();
    row.add(buildGuardedButton(DOC_READ, "Read"));
    row.add(buildGuardedButton(DOC_CREATE, "Create"));
    row.add(buildGuardedButton(DOC_DELETE, "Delete"));
    row.add(buildGuardedButton(ADMIN_ACCESS, "Admin"));
    return row;
  }

  private static void addIfAllowed(HorizontalLayout row, PermissionName perm, String label) {
    boolean allowed = ClientJSentinelContext.user()
        .map(u -> PermissionGuard.hasPermission(u, perm))
        .orElse(false);
    if (allowed) {
      Button button = new Button(label + " (" + perm.value() + ")",
          e -> success(perm));
      button.addThemeVariants(ButtonVariant.LUMO_PRIMARY, ButtonVariant.LUMO_SMALL);
      row.add(button);
    }
  }

  private static Button buildGuardedButton(PermissionName perm, String label) {
    Button button = new Button(label + " (" + perm.value() + ")", e -> {
      var subject = ClientJSentinelContext.user().orElse(null);
      try {
        PermissionGuard.requirePermission(subject, perm);
        success(perm);
      } catch (AccessDeniedException ex) {
        denied(perm);
      }
    });
    button.addThemeVariants(ButtonVariant.LUMO_TERTIARY, ButtonVariant.LUMO_SMALL);
    return button;
  }

  private static void success(PermissionName p) {
    Notification n = Notification.show("Local guard OK — '" + p.value() + "'",
        2500, Notification.Position.BOTTOM_END);
    n.addThemeVariants(NotificationVariant.LUMO_SUCCESS);
  }

  private static void denied(PermissionName p) {
    Notification n = Notification.show("Local guard denied — missing '" + p.value() + "'",
        3000, Notification.Position.BOTTOM_END);
    n.addThemeVariants(NotificationVariant.LUMO_ERROR);
  }

  private static HorizontalLayout securedUiButtonRow() {
    HorizontalLayout row = new HorizontalLayout();
    row.add(buildSecuredUiButton(DOC_READ, "Read"));
    row.add(buildSecuredUiButton(DOC_CREATE, "Create"));
    row.add(buildSecuredUiButton(DOC_DELETE, "Delete"));
    row.add(buildSecuredUiButton(ADMIN_ACCESS, "Admin"));
    Button policy = SecuredUi.button("Policy — " + DemoPolicyInitListener.POLICY_EDITOR_OR_ADMIN)
        .requiresPolicy(DemoPolicyInitListener.POLICY_EDITOR_OR_ADMIN)
        .disableWhenDenied()
        .onClick(e -> policySuccess())
        .build();
    policy.addThemeVariants(ButtonVariant.LUMO_CONTRAST, ButtonVariant.LUMO_SMALL);
    row.add(policy);
    return row;
  }

  private static Button buildSecuredUiButton(PermissionName perm, String label) {
    Button button = SecuredUi.button(label + " (" + perm.value() + ")")
        .requiresPermission(perm.value())
        .disableWhenDenied()
        .onClick(e -> success(perm))
        .build();
    button.addThemeVariants(ButtonVariant.LUMO_PRIMARY, ButtonVariant.LUMO_SMALL);
    return button;
  }

  private static void policySuccess() {
    Notification n = Notification.show(
        "Policy '" + DemoPolicyInitListener.POLICY_EDITOR_OR_ADMIN + "' granted.",
        2500, Notification.Position.BOTTOM_END);
    n.addThemeVariants(NotificationVariant.LUMO_SUCCESS);
  }

  private static Details buildAdminDetailsBlock() {
    VerticalLayout body = new VerticalLayout(
        new Paragraph(
            "Administrators see this entire Details block. The wrapper "
                + "is a vanilla com.vaadin.flow.component.details.Details; "
                + "SecuredUi.component(...) attaches the requirement and "
                + "the hideWhenDenied() visibility wiring without any "
                + "subclass."),
        new Span("This text would never reach a non-admin's browser."));
    body.setSpacing(false);
    body.getThemeList().add("spacing-xs");
    Details details = new Details("Admin-only diagnostics (admin:access)", body);
    return SecuredUi.component(details)
        .requiresPermission(ADMIN_ACCESS.value())
        .hideWhenDenied()
        .bind();
  }
}
