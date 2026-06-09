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
package com.svenruppert.jsentinel.demo.restclient.views;

import com.svenruppert.jsentinel.authorization.annotations.RequiresRole;
import com.svenruppert.jsentinel.logout.LogoutScope;
import com.svenruppert.jsentinel.logout.LogoutService;
import com.svenruppert.jsentinel.logout.SubjectId;
import com.svenruppert.jsentinel.authorization.api.SubjectStores;
import com.svenruppert.jsentinel.logout.vaadin.DefaultVaadinLogoutGateway;
import com.svenruppert.jsentinel.logout.vaadin.VaadinLogoutService;
import com.svenruppert.jsentinel.demo.restclient.backend.BackendClientProvider;
import com.svenruppert.jsentinel.demo.restclient.backend.BackendException;
import com.svenruppert.jsentinel.demo.restclient.backend.RemoteUser;
import com.svenruppert.jsentinel.demo.restclient.security.ClientJSentinelContext;
import com.svenruppert.jsentinel.demo.restclient.views.components.BackendOperationCard;
import com.svenruppert.jsentinel.demo.restclient.views.components.PermissionDemoCard;
import com.svenruppert.jsentinel.demo.restclient.views.standalone.AdminRolesView;
import com.svenruppert.jsentinel.demo.restclient.views.standalone.AdminStatusView;
import com.svenruppert.jsentinel.demo.restclient.views.standalone.AuditView;
import com.svenruppert.jsentinel.demo.restclient.views.standalone.DocumentsView;
import com.svenruppert.jsentinel.demo.restclient.views.standalone.NerdView;
import com.svenruppert.jsentinel.demo.restclient.views.standalone.PolicyDemoView;
import com.svenruppert.jsentinel.demo.restclient.views.standalone.ResourcePolicyDemoView;
import com.svenruppert.jsentinel.demo.restclient.views.standalone.StepUpDemoView;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.applayout.AppLayout;
import com.vaadin.flow.component.applayout.DrawerToggle;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.tabs.Tab;
import com.vaadin.flow.component.tabs.Tabs;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.router.RouterLink;

import java.util.HashMap;
import java.util.Map;

/**
 * Main shell. Restricted to authenticated users via {@code @RequiresRole}
 * — the framework's {@code AuthorizationListener} reroutes anyone without
 * the role to /login.
 */
@Route(MainView.NAV)
@RequiresRole({"ROLE_ADMIN", "ROLE_EDITOR", "ROLE_VIEWER"})
public class MainView extends AppLayout {

  public static final String NAV = "";

  private static final LogoutService LOGOUT_SERVICE =
      new VaadinLogoutService<>(
          SubjectStores.subjectStore(), RemoteUser.class,
          new DefaultVaadinLogoutGateway(),
          "/" + MyLoginView.NAV,
          /* closeVaadinSession= */ true,
          /* invalidateHttpSession= */ true);

  private final Map<Tab, Component> tab2Content = new HashMap<>();

  public MainView() {
    Span title = new Span("REST-client demo");
    title.addClassName("app-title");

    Button logoutBtn = new Button("Sign out", VaadinIcon.SIGN_OUT.create(), e -> logout());
    logoutBtn.addThemeVariants(ButtonVariant.LUMO_TERTIARY, ButtonVariant.LUMO_SMALL);
    logoutBtn.addClassName("navbar-btn");

    addToNavbar(new DrawerToggle(), title);
    addToNavbar(true, logoutBtn);
    addToDrawer(buildMenu());
    setContent(welcomeContent());
  }

  private Tabs buildMenu() {
    Tabs tabs = new Tabs();
    tabs.setOrientation(Tabs.Orientation.VERTICAL);
    tabs.addClassName("nav-tabs");

    Tab home = new Tab(VaadinIcon.HOME.create(), new Span("Home"));
    tab2Content.put(home, welcomeContent());
    tabs.add(home);

    Tab documents = new Tab(VaadinIcon.FILE.create(), new Span("Documents"));
    tab2Content.put(documents, sectionContent(
        "Documents workspace",
        "Lists, creates and deletes documents via the backend. Server-side "
            + "permissions decide the outcome.",
        new BackendOperationCard()));
    tabs.add(documents);

    Tab permissions = new Tab(VaadinIcon.LOCK.create(), new Span("Permission demo"));
    tab2Content.put(permissions, sectionContent(
        "Permission patterns",
        "UX adaptation vs. local guard, both against the cached RemoteUser "
            + "snapshot — local-only.",
        new PermissionDemoCard()));
    tabs.add(permissions);

    if (hasPermission("admin:roles")) {
      Tab rolesAdmin = new Tab(VaadinIcon.USER_CARD.create(), new Span("User roles"));
      tab2Content.put(rolesAdmin, new AdminRolesView());
      tabs.add(rolesAdmin);
    }

    if (hasPermission("audit:read")) {
      Tab audit = new Tab(VaadinIcon.CLIPBOARD_TEXT.create(), new Span("Audit log"));
      tab2Content.put(audit, new AuditView());
      tabs.add(audit);
    }

    Tab links = new Tab(VaadinIcon.CONNECT.create(), new Span("Standalone routes"));
    tab2Content.put(links, sectionContent(
        "View-level demonstrations",
        "Standalone routes — each guarded by a different annotation style. "
            + "Direct URLs work too. The framework reroutes if a user lacks "
            + "the required role/permission.",
        new VerticalLayout(
            new RouterLink("/documents — @RequiresPermission(\"document:read\")", DocumentsView.class),
            new RouterLink("/admin — @RequiresRole(\"ROLE_ADMIN\")", AdminStatusView.class),
            new RouterLink("/nerd — @VisibleForRoles({ADMIN, EDITOR})", NerdView.class),
            new RouterLink("/audit — @RequiresPermission(\"audit:read\")", AuditView.class),
            new RouterLink("/admin/roles — @RequiresPermission(\"admin:roles\")", AdminRolesView.class),
            new RouterLink("/policy-demo — @RequiresPolicy(\"documents.editor-or-admin\")", PolicyDemoView.class),
            new RouterLink("/resource-policy-demo — Policy + ResourcePredicates per click", ResourcePolicyDemoView.class),
            new RouterLink("/step-up-demo — @RequiresPolicy emits StepUpRequired → /step-up reroute", StepUpDemoView.class)
        )));
    tabs.add(links);

    tabs.addSelectedChangeListener(event -> setContent(tab2Content.get(event.getSelectedTab())));
    return tabs;
  }

  private static boolean hasPermission(String permissionValue) {
    return ClientJSentinelContext.user()
        .map(u -> u.permissions().stream().anyMatch(p -> permissionValue.equals(p.value())))
        .orElse(false);
  }

  private Component welcomeContent() {
    RemoteUser user = ClientJSentinelContext.user().orElse(null);
    String name = user == null ? "Guest" : user.displayName();
    String roles = user == null ? "(none)"
        : user.roles().stream().map(r -> r.value()).sorted().toList().toString();
    String perms = user == null ? "(none)"
        : user.permissions().stream().map(p -> p.value()).sorted().toList().toString();

    VerticalLayout layout = new VerticalLayout();
    layout.add(new H2("Welcome, " + name));
    layout.add(new Paragraph("Roles: " + roles));
    layout.add(new Paragraph("Permissions: " + perms));
    layout.add(new Paragraph(
        "Use the side navigation to explore the demo. The cached "
            + "RemoteUser drives view-level routing and UX hints; mutating "
            + "actions still call the backend, which is authoritative."));
    return layout;
  }

  private static Component sectionContent(String title, String subtitle, Component... extras) {
    VerticalLayout layout = new VerticalLayout();
    layout.add(new H2(title));
    layout.add(new Paragraph(subtitle));
    for (Component c : extras) layout.add(c);
    return layout;
  }

  private void logout() {
    String token = ClientJSentinelContext.token().orElse(null);
    if (token != null) {
      try {
        BackendClientProvider.client().logout(token);
      } catch (BackendException ignored) {
        // Best-effort — backend may already have invalidated the token.
      }
    }
    SubjectId subjectId = SubjectStores.subjectStore().currentSubject(RemoteUser.class)
        .map(u -> SubjectId.of(u.subjectId()))
        .orElse(SubjectId.of("anonymous"));
    LOGOUT_SERVICE.logout(subjectId, LogoutScope.CurrentSession);
  }
}
