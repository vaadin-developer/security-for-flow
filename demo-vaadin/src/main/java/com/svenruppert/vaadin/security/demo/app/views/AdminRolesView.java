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
package com.svenruppert.vaadin.security.demo.app.views;

import com.svenruppert.vaadin.security.authorization.annotations.RequiresPermission;
import com.svenruppert.vaadin.security.demo.app.security.model.DemoUserDirectory;
import com.svenruppert.vaadin.security.demo.app.security.model.DemoUserDirectoryProvider;
import com.svenruppert.vaadin.security.demo.app.security.model.MyUser;
import com.svenruppert.vaadin.security.demo.app.security.roles.AuthorizationRole;
import com.svenruppert.vaadin.security.demo.app.security.services.DemoSecurityVersionBumper;
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

import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Admin-only role-management UI. Lists every demo user with their current
 * roles and lets an admin add or revoke a role. Restricted by
 * {@code @RequiresPermission("admin:roles")}; the
 * {@link com.svenruppert.vaadin.security.demo.app.security.model.InMemoryDemoUserDirectory}
 * emits {@code RoleAssigned} / {@code RoleRevoked} audit events for each
 * mutation, so changes are visible in the {@code /audit}-route.
 * <p>
 * Demo-only — production deployments would replace the in-memory directory
 * with a real backend and would typically need a more elaborate
 * authorization model around who can edit whose roles.
 */
@Route(AdminRolesView.NAV)
@RequiresPermission("admin:roles")
public class AdminRolesView extends Composite<VerticalLayout> {

  public static final String NAV = "admin/roles";

  private final Grid<MyUser> grid = new Grid<>(MyUser.class, false);

  public AdminRolesView() {
    VerticalLayout root = getContent();
    root.addClassName("admin-roles-view");
    root.setSizeFull();
    root.setSpacing(false);
    root.getThemeList().add("spacing-s");

    root.add(new H1("Role administration"));
    root.add(new Paragraph(
        "Admin-only view (protected by @RequiresPermission(\"admin:roles\")). "
            + "Lists every demo user and lets you grant or revoke roles. "
            + "Each change emits a RoleAssigned / RoleRevoked audit event "
            + "visible in the /audit grid."));

    grid.setSizeFull();
    grid.setPageSize(50);
    grid.addColumn(MyUser::id).setHeader("Id").setWidth("4em").setFlexGrow(0);
    grid.addColumn(MyUser::name).setHeader("Name").setWidth("12em").setFlexGrow(0);
    grid.addColumn(user -> user.roles().stream()
            .map(Enum::name)
            .sorted()
            .toList()
            .toString())
        .setHeader("Roles").setFlexGrow(1);
    grid.addComponentColumn(this::buildRoleEditor).setHeader("Modify").setWidth("28em").setFlexGrow(0);
    grid.addComponentColumn(this::buildDeleteButton).setHeader("Delete").setWidth("7em").setFlexGrow(0);

    Button newUser = new Button("New user", VaadinIcon.PLUS_CIRCLE.create(), e -> openCreateUserDialog());
    newUser.addThemeVariants(ButtonVariant.LUMO_PRIMARY);

    Button back = new Button("Back to home", VaadinIcon.HOME.create(),
        e -> UI.getCurrent().navigate(MainView.class));
    back.addThemeVariants(ButtonVariant.LUMO_TERTIARY);

    HorizontalLayout toolbar = new HorizontalLayout(newUser, back);
    toolbar.setSpacing(true);

    root.add(toolbar);
    root.add(grid);
    root.setFlexGrow(1, grid);

    refresh();
  }

  private Button buildDeleteButton(MyUser user) {
    Button delete = new Button(VaadinIcon.TRASH.create(), e -> confirmDelete(user));
    delete.addThemeVariants(ButtonVariant.LUMO_ERROR, ButtonVariant.LUMO_TERTIARY,
        ButtonVariant.LUMO_SMALL);
    return delete;
  }

  private void confirmDelete(MyUser user) {
    ConfirmDialog dialog = new ConfirmDialog();
    dialog.setHeader("Delete user");
    dialog.setText("Permanently remove '" + user.name() + "' (id=" + user.id() + ")?");
    dialog.setCancelable(true);
    dialog.setConfirmText("Delete");
    dialog.setConfirmButtonTheme("error primary");
    dialog.addConfirmListener(e -> {
      DemoUserDirectoryProvider.directory().deleteUser(user.id());
      DemoSecurityVersionBumper.bump(user);
      success("Deleted user " + user.name() + ".");
      refresh();
    });
    dialog.open();
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
    ComboBox<AuthorizationRole> role = new ComboBox<>("Initial role");
    role.setItems(AuthorizationRole.values());
    role.setItemLabelGenerator(Enum::name);
    role.setRequiredIndicatorVisible(true);
    role.setValue(AuthorizationRole.USER);

    FormLayout form = new FormLayout(username, password, displayName, role);
    dialog.add(new H3("New demo user"), form);

    Button save = new Button("Create", VaadinIcon.CHECK.create(), e -> {
      String u = username.getValue() == null ? "" : username.getValue().trim();
      String p = password.getValue() == null ? "" : password.getValue();
      AuthorizationRole r = role.getValue();
      if (u.isEmpty() || p.isEmpty() || r == null) {
        warn("Username, password and initial role are required.");
        return;
      }
      if (DemoUserDirectoryProvider.directory().all().anyMatch(existing ->
          (displayName.getValue() != null && existing.name().equals(displayName.getValue()))
              || existing.id().equals(nextId()))) {
        // collision detection is best-effort for the demo
      }
      MyUser created = createMyUser(nextId(),
          displayName.getValue() == null || displayName.getValue().isBlank()
              ? u
              : displayName.getValue(),
          r);
      try {
        DemoUserDirectoryProvider.directory().addUser(u, p, created);
        success("Created user " + u + ".");
        dialog.close();
        refresh();
      } catch (RuntimeException failure) {
        warn("Could not create user: " + failure.getMessage());
      }
    });
    save.addThemeVariants(ButtonVariant.LUMO_PRIMARY);

    Button cancel = new Button("Cancel", e -> dialog.close());
    cancel.addThemeVariants(ButtonVariant.LUMO_TERTIARY);

    dialog.getFooter().add(cancel, save);
    dialog.open();
  }

  /**
   * Demo-only id generator. Picks {@code max(id) + 1} from the current
   * directory contents. Good enough for an in-memory single-process demo;
   * production stores would delegate to the underlying persistence layer.
   */
  private static Long nextId() {
    return DemoUserDirectoryProvider.directory().all()
        .mapToLong(MyUser::id)
        .max()
        .orElse(0L) + 1L;
  }

  private static MyUser createMyUser(Long id, String name, AuthorizationRole role) {
    EnumSet<AuthorizationRole> roles = EnumSet.of(AuthorizationRole.USER);
    roles.add(role);
    return new MyUser(id, name, roles);
  }

  private HorizontalLayout buildRoleEditor(MyUser user) {
    ComboBox<AuthorizationRole> roleSelect = new ComboBox<>();
    roleSelect.setItems(AuthorizationRole.values());
    roleSelect.setItemLabelGenerator(Enum::name);
    roleSelect.setPlaceholder("role");

    Button assign = new Button("Assign", VaadinIcon.PLUS.create(), e -> {
      AuthorizationRole role = roleSelect.getValue();
      if (role == null) {
        warn("Pick a role first.");
        return;
      }
      if (user.roles().contains(role)) {
        warn("User already has " + role.name() + ".");
        return;
      }
      DemoUserDirectoryProvider.directory().assignRole(user.id(), role);
      DemoSecurityVersionBumper.bump(user);
      success("Granted " + role.name() + " to " + user.name()
          + " — their session will be re-authenticated on next navigation.");
      refresh();
    });
    assign.addThemeVariants(ButtonVariant.LUMO_PRIMARY, ButtonVariant.LUMO_SMALL);

    Button revoke = new Button("Revoke", VaadinIcon.MINUS.create(), e -> {
      AuthorizationRole role = roleSelect.getValue();
      if (role == null) {
        warn("Pick a role first.");
        return;
      }
      if (!user.roles().contains(role)) {
        warn("User does not have " + role.name() + ".");
        return;
      }
      DemoUserDirectoryProvider.directory().revokeRole(user.id(), role);
      DemoSecurityVersionBumper.bump(user);
      success("Revoked " + role.name() + " from " + user.name()
          + " — their session will be re-authenticated on next navigation.");
      refresh();
    });
    revoke.addThemeVariants(ButtonVariant.LUMO_TERTIARY, ButtonVariant.LUMO_SMALL);

    HorizontalLayout row = new HorizontalLayout(roleSelect, assign, revoke);
    row.setSpacing(true);
    return row;
  }

  private void refresh() {
    DemoUserDirectory directory = DemoUserDirectoryProvider.directory();
    List<MyUser> users = directory.all()
        .sorted(Comparator.comparing(MyUser::id))
        .toList();
    grid.setItems(users);
  }

  private static void success(String message) {
    Notification notification = Notification.show(
        message, 2500, Notification.Position.BOTTOM_END);
    notification.addThemeVariants(NotificationVariant.LUMO_SUCCESS);
  }

  private static void warn(String message) {
    Notification notification = Notification.show(
        message, 3000, Notification.Position.BOTTOM_END);
    notification.addThemeVariants(NotificationVariant.LUMO_WARNING);
  }

  /** Test seam — full set of selectable roles (the ComboBox items). */
  static Set<AuthorizationRole> selectableRoles() {
    return EnumSet.allOf(AuthorizationRole.class);
  }
}
