package com.svenruppert.jsentinel.demo.skill.vaadin.views.admin;

import com.svenruppert.jsentinel.authorization.annotations.RequiresPermission;
import com.vaadin.flow.component.Composite;
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
import com.svenruppert.jsentinel.demo.skill.vaadin.views.HomeButton;
import com.svenruppert.jsentinel.demo.skill.vaadin.views.MainLayout;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.model.UserDirectory;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.model.UserDirectoryProvider;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.model.User;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.roles.AuthorizationRole;

import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;

/**
 * User + role admin. Restricted by
 * {@code @RequiresPermission("admin:roles")}.
 *
 * <ul>
 *   <li>List every user with their roles.</li>
 *   <li>Assign / revoke a role on any row.</li>
 *   <li>Create a new user via dialog.</li>
 *   <li>Delete a user via confirm dialog.</li>
 * </ul>
 *
 * <p>Every mutation emits a {@code RoleAssigned} / {@code RoleRevoked} /
 * {@code UserCreated} / {@code UserDeleted} audit event — visible in
 * the {@code /audit} grid.
 */
@Route(value = AdminRolesView.NAV, layout = MainLayout.class)
@RequiresPermission("admin:roles")
public class AdminRolesView extends Composite<VerticalLayout> {

  public static final String NAV = "admin/roles";

  private final Grid<User> grid = new Grid<>(User.class, false);

  public AdminRolesView() {
    VerticalLayout root = getContent();
    root.setSizeFull();
    root.setSpacing(false);
    root.getThemeList().add("spacing-s");

    root.add(new H1("Role administration"));
    root.add(new Paragraph(
        "Admin-only. Mutations emit RoleAssigned / RoleRevoked / UserCreated "
            + "/ UserDeleted audit events, visible in the /audit grid."));

    grid.setSizeFull();
    grid.setPageSize(50);
    grid.addColumn(User::id).setHeader("Id").setWidth("4em").setFlexGrow(0);
    grid.addColumn(User::name).setHeader("Name").setWidth("14em").setFlexGrow(0);
    grid.addColumn(u -> u.roles().stream().map(Enum::name).sorted().toList().toString())
        .setHeader("Roles").setFlexGrow(1);
    grid.addComponentColumn(this::buildRoleEditor).setHeader("Modify").setWidth("28em").setFlexGrow(0);
    grid.addComponentColumn(this::buildDeleteButton).setHeader("Delete").setWidth("7em").setFlexGrow(0);

    Button newUser = new Button("New user", VaadinIcon.PLUS_CIRCLE.create(), e -> openCreateUserDialog());
    newUser.addThemeVariants(ButtonVariant.LUMO_PRIMARY);

    HorizontalLayout toolbar = new HorizontalLayout(newUser);
    HomeButton.forStandalone(getClass()).ifPresent(toolbar::add);
    toolbar.setSpacing(true);
    root.add(toolbar);
    root.add(grid);
    root.setFlexGrow(1, grid);
    refresh();
  }

  private HorizontalLayout buildRoleEditor(User user) {
    ComboBox<AuthorizationRole> select = new ComboBox<>();
    select.setItems(AuthorizationRole.values());
    select.setItemLabelGenerator(Enum::name);
    select.setPlaceholder("role");

    Button assign = new Button("Assign", VaadinIcon.PLUS.create(), e -> {
      AuthorizationRole role = select.getValue();
      if (role == null) {
        warn("Pick a role first.");
        return;
      }
      if (user.roles().contains(role)) {
        warn("Already assigned.");
        return;
      }
      UserDirectoryProvider.directory().assignRole(user.id(), role);
      success("Granted " + role.name() + " to " + user.name() + ".");
      refresh();
    });
    assign.addThemeVariants(ButtonVariant.LUMO_PRIMARY, ButtonVariant.LUMO_SMALL);

    Button revoke = new Button("Revoke", VaadinIcon.MINUS.create(), e -> {
      AuthorizationRole role = select.getValue();
      if (role == null) {
        warn("Pick a role first.");
        return;
      }
      if (!user.roles().contains(role)) {
        warn("Not assigned.");
        return;
      }
      UserDirectoryProvider.directory().revokeRole(user.id(), role);
      success("Revoked " + role.name() + " from " + user.name() + ".");
      refresh();
    });
    revoke.addThemeVariants(ButtonVariant.LUMO_TERTIARY, ButtonVariant.LUMO_SMALL);

    HorizontalLayout row = new HorizontalLayout(select, assign, revoke);
    row.setSpacing(true);
    return row;
  }

  private Button buildDeleteButton(User user) {
    Button delete = new Button(VaadinIcon.TRASH.create(), e -> confirmDelete(user));
    delete.addThemeVariants(ButtonVariant.LUMO_ERROR, ButtonVariant.LUMO_TERTIARY,
        ButtonVariant.LUMO_SMALL);
    return delete;
  }

  private void confirmDelete(User user) {
    ConfirmDialog dialog = new ConfirmDialog();
    dialog.setHeader("Delete user");
    dialog.setText("Permanently remove '" + user.name() + "' (id=" + user.id() + ")?");
    dialog.setCancelable(true);
    dialog.setConfirmText("Delete");
    dialog.setConfirmButtonTheme("error primary");
    dialog.addConfirmListener(e -> {
      UserDirectoryProvider.directory().deleteUser(user.id());
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
    dialog.add(new H3("New user"), form);

    Button save = new Button("Create", VaadinIcon.CHECK.create(), e -> {
      String u = username.getValue() == null ? "" : username.getValue().trim();
      String p = password.getValue() == null ? "" : password.getValue();
      AuthorizationRole r = role.getValue();
      if (u.isEmpty() || p.isEmpty() || r == null) {
        warn("Username, password and initial role are required.");
        return;
      }
      String display = displayName.getValue() == null || displayName.getValue().isBlank()
          ? u : displayName.getValue();
      User created = new User(nextId(), display,
          EnumSet.of(AuthorizationRole.USER, r));
      try {
        UserDirectoryProvider.directory().addUser(u, p, created);
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

  private static Long nextId() {
    return UserDirectoryProvider.directory().all()
        .mapToLong(User::id)
        .max()
        .orElse(0L) + 1L;
  }

  private void refresh() {
    UserDirectory directory = UserDirectoryProvider.directory();
    List<User> users = directory.all()
        .sorted(Comparator.comparing(User::id))
        .toList();
    grid.setItems(users);
  }

  private static void success(String message) {
    Notification n = Notification.show(message, 2500, Notification.Position.BOTTOM_END);
    n.addThemeVariants(NotificationVariant.LUMO_SUCCESS);
  }

  private static void warn(String message) {
    Notification n = Notification.show(message, 3000, Notification.Position.BOTTOM_END);
    n.addThemeVariants(NotificationVariant.LUMO_WARNING);
  }
}
