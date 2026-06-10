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

import com.svenruppert.jsentinel.starter.routes.SecureRoute;
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

/**
 * V00.72 starter showcase — single-annotation declarative route gating.
 *
 * <p>The {@link SecureRoute @SecureRoute} annotation combines role,
 * permission and policy checks in one place. Semantics
 * (most-restrictive-wins): if more than one axis is populated, all
 * underlying decisions must be {@code Granted} for the route to render.
 * Non-Granted outcomes follow the precedence
 * {@code Unauthenticated > Forbidden > StepUpRequired > Granted}.
 *
 * <p>This demo route requires:
 * <ul>
 *   <li>one of the roles {@code ADMIN} or {@code NERD}, and</li>
 *   <li>the permission {@code demo:view}.</li>
 * </ul>
 *
 * <p>Users with {@code NERD} but without {@code demo:view} are rejected;
 * users with {@code demo:view} but without {@code ADMIN} / {@code NERD}
 * are rejected; only the intersection passes. Compare with the sibling
 * views ({@link NerdView} uses {@code @VisibleFor}, {@link AuditView}
 * uses {@code @RequiresPermission}) to see the three declarative styles
 * side by side.
 */
@Route(SecureRouteDemoView.NAV)
@SecureRoute(roles = {"ADMIN", "NERD"}, permissions = "demo:view")
public class SecureRouteDemoView extends Composite<Div> {

  public static final String NAV = "secure-route-demo";

  public SecureRouteDemoView() {
    HorizontalLayout badges = new HorizontalLayout();
    Span adminBadge = new Span("ADMIN");
    adminBadge.getElement().getThemeList().add("badge error");
    Span nerdBadge = new Span("NERD");
    nerdBadge.getElement().getThemeList().add("badge contrast");
    Span permBadge = new Span("demo:view");
    permBadge.getElement().getThemeList().add("badge success");
    badges.add(adminBadge, nerdBadge, permBadge);

    H1 heading = new H1("@SecureRoute demo");

    Paragraph description = new Paragraph(
        "This route is protected by a single @SecureRoute(roles = {\"ADMIN\", "
            + "\"NERD\"}, permissions = \"demo:view\") annotation. The starter's "
            + "SecureRouteEvaluator combines both axes with most-restrictive-wins "
            + "semantics: only subjects that hold (ADMIN or NERD) AND demo:view "
            + "are granted. Everyone else gets rerouted by the framework.");

    Paragraph compare = new Paragraph(
        "Compare with: NerdView uses the project-specific @VisibleFor "
            + "annotation, AuditView uses the core @RequiresPermission, "
            + "AdminRolesView uses @RequiresPermission. @SecureRoute is the "
            + "max-comfort one-liner that covers all three axes in a single "
            + "place — useful when a route needs more than one check.");

    Button back = new Button("Back to home", VaadinIcon.HOME.create(),
        e -> UI.getCurrent().navigate(MainView.class));
    back.addThemeVariants(ButtonVariant.LUMO_TERTIARY);

    VerticalLayout layout = new VerticalLayout(
        new HorizontalLayout(badges, heading),
        description,
        compare,
        back);
    layout.setSpacing(false);
    layout.getThemeList().add("spacing-s");
    layout.addClassNames("workspace", "workspace-secure-route");

    getContent().add(layout);
  }
}
