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
package com.svenruppert.jsentinel.demo.app.views.components;

import com.svenruppert.jsentinel.components.SecuredRouterLink;
import com.svenruppert.jsentinel.components.SecuredVisibility.Requirement;
import com.svenruppert.jsentinel.components.SecuredVisibilityMode;
import com.svenruppert.jsentinel.demo.app.security.permissions.DemoPermission;
import com.svenruppert.jsentinel.demo.app.views.AdminRolesView;
import com.svenruppert.jsentinel.demo.app.views.AdminSessionsView;
import com.svenruppert.jsentinel.demo.app.views.AdminView;
import com.svenruppert.jsentinel.demo.app.views.AuditView;
import com.svenruppert.jsentinel.demo.app.views.NerdView;
import com.svenruppert.jsentinel.demo.app.views.PublicView;
import com.svenruppert.jsentinel.demo.app.views.SecureRouteDemoView;
import com.svenruppert.jsentinel.starter.ui.SecuredUi;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.H3;
import com.vaadin.flow.component.html.H4;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.RouterLink;

/**
 * Card with router links to the three standalone demo views. Demonstrates
 * view-level security: the link is rendered for everyone, but navigation is
 * blocked by {@code AuthorizationListener} for users without the matching
 * role. The user sees the framework reroute kick in.
 */
public class ViewNavigationCard extends Composite<VerticalLayout> {

  public ViewNavigationCard() {
    VerticalLayout root = getContent();
    root.addClassName("view-navigation-card");
    root.setSpacing(false);
    root.getThemeList().add("spacing-s");

    root.add(new H3("Standalone views (view-level security)"));
    root.add(new Paragraph(
        "These links navigate to standalone routes. The links are visible "
            + "to everyone, but navigation is blocked by the framework's "
            + "AuthorizationListener for users without the required role. "
            + "Try opening them after logging in as different demo users."));

    HorizontalLayout links = new HorizontalLayout();
    links.setSpacing(true);
    links.add(new RouterLink("/admin (ADMIN)", AdminView.class));
    links.add(new RouterLink("/admin/roles (admin:roles)", AdminRolesView.class));
    links.add(new RouterLink("/nerd (ADMIN, NERD)", NerdView.class));
    links.add(new RouterLink("/audit (audit:read)", AuditView.class));
    links.add(new RouterLink("/public (open)", PublicView.class));
    root.add(links);

    root.add(new H4("Phase-8a — SecuredRouterLink (UX adaptation)"));
    root.add(new Paragraph(
        "Same destinations rendered through SecuredRouterLink. Links that "
            + "the current subject cannot reach are HIDE-d completely (gone "
            + "from the layout) or DISABLE-d (rendered greyed out). The "
            + "framework still enforces the view-level guard server-side — "
            + "this is purely a UX layer on top."));
    HorizontalLayout securedLinks = new HorizontalLayout();
    securedLinks.setSpacing(true);
    securedLinks.add(new SecuredRouterLink(
        "/admin/roles (HIDE)", AdminRolesView.class,
        Requirement.permission(DemoPermission.ADMIN_ROLES.permissionName())));
    securedLinks.add(new SecuredRouterLink(
        "/admin/sessions (HIDE)", AdminSessionsView.class,
        Requirement.permission(DemoPermission.ADMIN_SESSIONS.permissionName())));
    securedLinks.add(new SecuredRouterLink(
        "/audit (DISABLE)", AuditView.class,
        Requirement.permission(DemoPermission.AUDIT_READ.permissionName()),
        SecuredVisibilityMode.DISABLE));
    root.add(securedLinks);

    root.add(new H4("Pattern D — V00.72 SecuredUi.link (max comfort)"));
    root.add(new Paragraph(
        "Same destinations as the Phase-8a block above, but assembled "
            + "through the starter's SecuredUi.link(...) fluent builder — "
            + "no explicit Requirement construction, no SecuredVisibilityMode "
            + "constant in the constructor. Mode is selected through "
            + ".hideWhenDenied() / .disableWhenDenied(). The trailing link "
            + "navigates to /secure-route-demo (annotated with @SecureRoute) "
            + "and shows the role-based requirement form."));
    HorizontalLayout securedUiLinks = new HorizontalLayout();
    securedUiLinks.setSpacing(true);
    securedUiLinks.add(SecuredUi.link()
        .to(AdminRolesView.class)
        .text("/admin/roles · SecuredUi HIDE")
        .requiresPermission(DemoPermission.ADMIN_ROLES.permissionName().value())
        .hideWhenDenied()
        .build());
    securedUiLinks.add(SecuredUi.link()
        .to(AdminSessionsView.class)
        .text("/admin/sessions · SecuredUi HIDE")
        .requiresPermission(DemoPermission.ADMIN_SESSIONS.permissionName().value())
        .hideWhenDenied()
        .build());
    securedUiLinks.add(SecuredUi.link()
        .to(AuditView.class)
        .text("/audit · SecuredUi DISABLE")
        .requiresPermission(DemoPermission.AUDIT_READ.permissionName().value())
        .disableWhenDenied()
        .build());
    securedUiLinks.add(SecuredUi.link()
        .to(SecureRouteDemoView.class)
        .text("/secure-route-demo · SecuredUi DISABLE (ADMIN, NERD)")
        .requiresRole("ADMIN", "NERD")
        .disableWhenDenied()
        .build());
    root.add(securedUiLinks);
  }
}
