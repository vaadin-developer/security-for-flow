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
package com.svenruppert.vaadin.security.demo.restclient.views.standalone;

import com.svenruppert.vaadin.security.authorization.annotations.RequiresPermission;
import com.svenruppert.vaadin.security.demo.restclient.backend.BackendClientProvider;
import com.svenruppert.vaadin.security.demo.restclient.backend.BackendException;
import com.svenruppert.vaadin.security.demo.restclient.backend.RemoteUserEntry;
import com.svenruppert.vaadin.security.demo.restclient.security.ClientJSentinelContext;
import com.svenruppert.vaadin.security.demo.restclient.views.MainView;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.combobox.ComboBox;
import com.vaadin.flow.component.confirmdialog.ConfirmDialog;
import com.vaadin.flow.component.dialog.Dialog;
import com.vaadin.flow.component.formlayout.FormLayout;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.H3;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationVariant;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.router.Route;

import java.util.List;

/**
 * Admin-only role-management UI for the rest-client demo. Reads the user
 * list from the backend ({@code GET /api/admin/users}) and pushes role
 * changes via {@code PUT /api/admin/users/{username}}. The backend stores
 * one role per user, so this view is a "set role" UI (ComboBox + Apply)
 * rather than an additive assign/revoke pattern.
 * <p>
 * Restricted by {@code @RequiresPermission("admin:roles")}. The backend
 * grants {@code admin:roles} to {@code ROLE_ADMIN}; it arrives on the
 * {@code RemoteUser} snapshot at login time, so the framework's
 * {@code AuthorizationListener} reroutes non-admin subjects before this
 * view renders.
 */
@Route(AdminRolesView.NAV)
@RequiresPermission("admin:roles")
public class AdminRolesView extends Composite<VerticalLayout> {

  public static final String NAV = "admin/roles";

  /** Demo backend uses the closed set {@code ROLE_ADMIN / ROLE_EDITOR / ROLE_VIEWER}. */
  private static final List<String> KNOWN_ROLES = List.of("ROLE_ADMIN", "ROLE_EDITOR", "ROLE_VIEWER");

  private final Grid<RemoteUserEntry> grid = new Grid<>(RemoteUserEntry.class, false);

  public AdminRolesView() {
    VerticalLayout root = getContent();
    root.addClassName("admin-roles-view");
    root.setSizeFull();
    root.setSpacing(false);
    root.getThemeList().add("spacing-s");

    root.add(new H1("Role administration (backend-driven)"));
    root.add(new Paragraph(
        "Lists every backend user via GET /api/admin/users and pushes role "
            + "changes via PUT /api/admin/users/{username}. The backend "
            + "stores one role per user, so this is a single-role select "
            + "form. Each change emits RoleRevoked + RoleAssigned in the "
            + "backend's audit log."));

    grid.setSizeFull();
    grid.setPageSize(50);
    grid.addColumn(RemoteUserEntry::username).setHeader("Username").setWidth("12em").setFlexGrow(0);
    grid.addColumn(RemoteUserEntry::displayName).setHeader("Display name").setWidth("14em").setFlexGrow(0);
    grid.addColumn(RemoteUserEntry::role).setHeader("Role").setWidth("12em").setFlexGrow(0);
    grid.addComponentColumn(this::buildRoleEditor).setHeader("Modify").setFlexGrow(1);
    grid.addComponentColumn(this::buildDeleteButton).setHeader("Delete").setWidth("7em").setFlexGrow(0);

    Button newUser = new Button("New user", VaadinIcon.PLUS_CIRCLE.create(), e -> openCreateUserDialog());
    newUser.addThemeVariants(ButtonVariant.LUMO_PRIMARY);

    Button refresh = new Button("Refresh", VaadinIcon.REFRESH.create(), e -> refresh());
    refresh.addThemeVariants(ButtonVariant.LUMO_TERTIARY);

    Button back = new Button("Back to home", VaadinIcon.HOME.create(),
        e -> UI.getCurrent().navigate(MainView.class));
    back.addThemeVariants(ButtonVariant.LUMO_TERTIARY);

    HorizontalLayout toolbar = new HorizontalLayout(newUser, refresh, back);
    toolbar.setSpacing(true);

    root.add(toolbar);
    root.add(grid);
    root.setFlexGrow(1, grid);

    refresh();
  }

  private Button buildDeleteButton(RemoteUserEntry entry) {
    Button delete = new Button(VaadinIcon.TRASH.create(), e -> confirmDelete(entry));
    delete.addThemeVariants(ButtonVariant.LUMO_ERROR, ButtonVariant.LUMO_TERTIARY,
        ButtonVariant.LUMO_SMALL);
    return delete;
  }

  private void confirmDelete(RemoteUserEntry entry) {
    ConfirmDialog dialog = new ConfirmDialog();
    dialog.setHeader("Delete user");
    dialog.setText("Permanently remove '" + entry.username() + "'?");
    dialog.setCancelable(true);
    dialog.setConfirmText("Delete");
    dialog.setConfirmButtonTheme("error primary");
    dialog.addConfirmListener(e -> performDelete(entry.username()));
    dialog.open();
  }

  private void performDelete(String username) {
    String token = ClientJSentinelContext.token().orElse(null);
    if (token == null) {
      warn("Not authenticated.");
      return;
    }
    try {
      BackendClientProvider.client().deleteUser(token, username);
      success("Deleted user " + username + ".");
      refresh();
    } catch (BackendException ex) {
      warn(switch (ex.kind()) {
        case Forbidden -> "Backend denied the deletion (forbidden).";
        case NotFound -> "User not found.";
        case Unauthenticated -> "Session expired — please sign in again.";
        default -> "Backend error: " + ex.getMessage();
      });
    }
  }

  private void openCreateUserDialog() {
    Dialog dialog = new Dialog();
    dialog.setHeaderTitle("Create user");

    TextField username = new TextField("Username");
    username.setRequiredIndicatorVisible(true);
    PasswordField password = new PasswordField("Password");
    password.setRequiredIndicatorVisible(true);
    TextField displayName = new TextField("Display name");
    displayName.setPlaceholder("(defaults to username)");
    ComboBox<String> role = new ComboBox<>("Initial role");
    role.setItems(KNOWN_ROLES);
    role.setRequiredIndicatorVisible(true);
    role.setValue("ROLE_VIEWER");

    FormLayout form = new FormLayout(username, password, displayName, role);
    dialog.add(new H3("New backend user"), form);

    Button save = new Button("Create", VaadinIcon.CHECK.create(), e -> {
      String u = username.getValue() == null ? "" : username.getValue().trim();
      String p = password.getValue() == null ? "" : password.getValue();
      String r = role.getValue();
      if (u.isEmpty() || p.isEmpty() || r == null) {
        warn("Username, password and initial role are required.");
        return;
      }
      performCreate(u, p,
          displayName.getValue() == null || displayName.getValue().isBlank()
              ? null
              : displayName.getValue(),
          r,
          dialog);
    });
    save.addThemeVariants(ButtonVariant.LUMO_PRIMARY);

    Button cancel = new Button("Cancel", e -> dialog.close());
    cancel.addThemeVariants(ButtonVariant.LUMO_TERTIARY);

    dialog.getFooter().add(cancel, save);
    dialog.open();
  }

  private void performCreate(String username, String password, String displayName,
                             String role, Dialog dialog) {
    String token = ClientJSentinelContext.token().orElse(null);
    if (token == null) {
      warn("Not authenticated.");
      return;
    }
    try {
      RemoteUserEntry created = BackendClientProvider.client()
          .createUser(token, username, password, displayName, role);
      success("Created user " + created.username() + " (" + created.role() + ").");
      dialog.close();
      refresh();
    } catch (BackendException ex) {
      warn(switch (ex.kind()) {
        case Conflict -> "Username already exists.";
        case BadRequest -> "Backend rejected the input.";
        case Forbidden -> "Backend denied the creation (forbidden).";
        case Unauthenticated -> "Session expired — please sign in again.";
        default -> "Backend error: " + ex.getMessage();
      });
    }
  }

  private HorizontalLayout buildRoleEditor(RemoteUserEntry entry) {
    ComboBox<String> roleSelect = new ComboBox<>();
    roleSelect.setItems(KNOWN_ROLES);
    roleSelect.setValue(entry.role());
    roleSelect.setAllowCustomValue(false);

    Button apply = new Button("Apply", VaadinIcon.CHECK.create(), e -> {
      String selected = roleSelect.getValue();
      if (selected == null || selected.equals(entry.role())) {
        warn("Pick a different role first.");
        return;
      }
      apply(entry.username(), selected);
    });
    apply.addThemeVariants(ButtonVariant.LUMO_PRIMARY, ButtonVariant.LUMO_SMALL);

    HorizontalLayout row = new HorizontalLayout(roleSelect, apply);
    row.setSpacing(true);
    return row;
  }

  private void apply(String username, String newRole) {
    String token = ClientJSentinelContext.token().orElse(null);
    if (token == null) {
      warn("Not authenticated.");
      return;
    }
    try {
      RemoteUserEntry updated = BackendClientProvider.client().setUserRole(token, username, newRole);
      success("Role of " + updated.username() + " is now " + updated.role() + ".");
      refresh();
    } catch (BackendException ex) {
      warn(switch (ex.kind()) {
        case Forbidden -> "Backend denied the change (forbidden).";
        case NotFound -> "User not found.";
        case BadRequest -> "Backend rejected the role.";
        case Unauthenticated -> "Session expired — please sign in again.";
        default -> "Backend error: " + ex.getMessage();
      });
    }
  }

  private void refresh() {
    String token = ClientJSentinelContext.token().orElse(null);
    if (token == null) {
      grid.setItems(List.of());
      return;
    }
    try {
      List<RemoteUserEntry> users = BackendClientProvider.client().listUsers(token);
      grid.setItems(users);
    } catch (BackendException ex) {
      grid.setItems(List.of());
      warn("Could not load users: " + ex.getMessage());
    }
  }

  private static void success(String message) {
    Notification notification = Notification.show(
        message, 2500, Notification.Position.BOTTOM_END);
    notification.addThemeVariants(NotificationVariant.LUMO_SUCCESS);
  }

  private static void warn(String message) {
    Notification notification = Notification.show(
        message, 3500, Notification.Position.BOTTOM_END);
    notification.addThemeVariants(NotificationVariant.LUMO_WARNING);
  }
}
