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

import com.svenruppert.vaadin.security.action.ActionAuthorizationService;
import com.svenruppert.vaadin.security.action.ActionPermission;
import com.svenruppert.vaadin.security.authorization.api.AccessDeniedException;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SubjectStores;
import com.svenruppert.vaadin.security.components.SecuredButton;
import com.svenruppert.vaadin.security.components.SecuredVisibility.Requirement;
import com.svenruppert.vaadin.security.components.SecuredVisibilityMode;
import com.svenruppert.vaadin.security.demo.app.security.model.MyUser;
import com.svenruppert.vaadin.security.demo.app.security.permissions.DemoPermission;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.html.H3;
import com.vaadin.flow.component.html.H4;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationVariant;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;

import java.util.Optional;

/**
 * Reusable card that exercises the three demo permissions twice: once with
 * UX adaptation (button only visible when the permission is present) and
 * once with server-side enforcement (button always visible, request fails
 * on click for users without the permission).
 * <p>
 * Both patterns route through the
 * {@link ActionAuthorizationService} SPI — UX hints via
 * {@link ActionAuthorizationService#isAllowed isAllowed}, server-side
 * enforcement via
 * {@link ActionAuthorizationService#requireAllowed requireAllowed} which
 * additionally emits an {@code ACTION_DENIED} audit event.
 */
public class PermissionDemoCard extends Composite<VerticalLayout> {

  public PermissionDemoCard() {
    VerticalLayout root = getContent();
    root.addClassName("permission-demo-card");
    root.setSpacing(false);
    root.getThemeList().add("spacing-s");

    root.add(new H3("Permission demonstration"));

    root.add(new H4("Pattern A — UX adaptation (visible only when allowed)"));
    root.add(new Paragraph(
        "Buttons are added to the layout only if the current user has the "
            + "required permission. Hiding UI is purely a UX hint, never a "
            + "security boundary."));
    root.add(buildVisibilityRow());

    root.add(new H4("Pattern B — Server-side guard (always visible, checked on click)"));
    root.add(new Paragraph(
        "Buttons are always visible. On click, the click handler calls "
            + "ActionAuthorizationService.requireAllowed(...) before performing "
            + "the action. That call is the actual protection boundary; it "
            + "emits an ACTION_DENIED audit event on failure."));
    root.add(buildEnforcementRow());

    root.add(new H4("Pattern C — Phase-8a SecuredButton (declarative)"));
    root.add(new Paragraph(
        "Same UX adaptation as Pattern A, but expressed declaratively via "
            + "SecuredButton + SecuredVisibility.Requirement. The framework "
            + "looks up the current subject's permissions through "
            + "SecurityServiceResolver — no manual isAllowed plumbing per "
            + "button. DISABLE mode keeps the affordance visible (greyed "
            + "out) to teach the user about the missing permission."));
    root.add(buildSecuredButtonRow());
  }

  private HorizontalLayout buildVisibilityRow() {
    HorizontalLayout row = new HorizontalLayout();
    row.setSpacing(true);
    addIfAllowed(row, DemoPermission.DEMO_VIEW, "View something");
    addIfAllowed(row, DemoPermission.DEMO_EDIT, "Edit something");
    addIfAllowed(row, DemoPermission.DEMO_ADMIN, "Admin operation");
    if (row.getComponentCount() == 0) {
      row.add(new Span("(No demo permissions for this user — nothing visible.)"));
    }
    return row;
  }

  private HorizontalLayout buildEnforcementRow() {
    HorizontalLayout row = new HorizontalLayout();
    row.setSpacing(true);
    row.add(buildGuardedButton(DemoPermission.DEMO_VIEW, "View something"));
    row.add(buildGuardedButton(DemoPermission.DEMO_EDIT, "Edit something"));
    row.add(buildGuardedButton(DemoPermission.DEMO_ADMIN, "Admin operation"));
    return row;
  }

  private HorizontalLayout buildSecuredButtonRow() {
    HorizontalLayout row = new HorizontalLayout();
    row.setSpacing(true);
    row.add(buildSecuredButton(DemoPermission.DEMO_VIEW, "View something"));
    row.add(buildSecuredButton(DemoPermission.DEMO_EDIT, "Edit something"));
    row.add(buildSecuredButton(DemoPermission.DEMO_ADMIN, "Admin operation"));
    return row;
  }

  private static SecuredButton buildSecuredButton(DemoPermission permission, String label) {
    SecuredButton button = new SecuredButton(
        label + " (" + permission.permissionName().value() + ")",
        Requirement.permission(permission.permissionName()),
        SecuredVisibilityMode.DISABLE);
    button.addThemeVariants(ButtonVariant.LUMO_PRIMARY, ButtonVariant.LUMO_SMALL);
    button.addClickListener(event -> success(permission.actionPermission()));
    return button;
  }

  private static void addIfAllowed(HorizontalLayout row, DemoPermission permission, String label) {
    if (isAllowed(permission.actionPermission())) {
      Button button = new Button(label + " (" + permission.permissionName().value() + ")",
          event -> success(permission.actionPermission()));
      button.addThemeVariants(ButtonVariant.LUMO_PRIMARY, ButtonVariant.LUMO_SMALL);
      row.add(button);
    }
  }

  private static Button buildGuardedButton(DemoPermission permission, String label) {
    Button button = new Button(
        label + " (" + permission.permissionName().value() + ")",
        event -> {
          MyUser user = currentUser().orElse(null);
          try {
            actionAuthorizationService().requireAllowed(user, permission.actionPermission());
            success(permission.actionPermission());
          } catch (AccessDeniedException e) {
            denied(permission.actionPermission());
          }
        });
    button.addThemeVariants(ButtonVariant.LUMO_TERTIARY, ButtonVariant.LUMO_SMALL);
    return button;
  }

  private static boolean isAllowed(ActionPermission permission) {
    return currentUser()
        .map(user -> actionAuthorizationService().isAllowed(user, permission))
        .orElse(false);
  }

  private static ActionAuthorizationService<MyUser> actionAuthorizationService() {
    return SecurityServiceResolver.actionAuthorizationService();
  }

  private static Optional<MyUser> currentUser() {
    return SubjectStores.subjectStore().currentSubject(MyUser.class);
  }

  private static void success(ActionPermission permission) {
    Notification notification = Notification.show(
        "OK — '" + permission.name() + "' executed.", 2500, Notification.Position.BOTTOM_END);
    notification.addThemeVariants(NotificationVariant.LUMO_SUCCESS);
  }

  private static void denied(ActionPermission permission) {
    Notification notification = Notification.show(
        "Denied — missing '" + permission.name() + "'.", 3000, Notification.Position.BOTTOM_END);
    notification.addThemeVariants(NotificationVariant.LUMO_ERROR);
  }
}
