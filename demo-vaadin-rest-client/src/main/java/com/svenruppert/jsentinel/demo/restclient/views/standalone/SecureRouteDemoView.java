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

import com.svenruppert.jsentinel.starter.routes.SecureRoute;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;

/**
 * Stil D — V00.72 starter {@link SecureRoute @SecureRoute} annotation.
 *
 * <p>This view sits alongside the four standalone demos for the
 * REST-client demo:
 * <ul>
 *   <li>{@link DocumentsView} — core {@code @RequiresPermission}</li>
 *   <li>{@link AdminStatusView} — core {@code @RequiresRole}</li>
 *   <li>{@link NerdView} — project-specific {@code @VisibleForRoles}</li>
 *   <li>{@link PolicyDemoView} — core {@code @RequiresPolicy}</li>
 * </ul>
 *
 * <p>{@code @SecureRoute} combines all three axes (role, permission,
 * policy) in a single annotation with documented most-restrictive-wins
 * semantics. This route requires the {@code ROLE_EDITOR} or
 * {@code ROLE_ADMIN} role <em>and</em> the {@code document:read}
 * permission <em>and</em> a positive {@code documents.editor-or-admin}
 * policy decision.
 */
@Route(SecureRouteDemoView.NAV)
@SecureRoute(
    roles = {"ROLE_EDITOR", "ROLE_ADMIN"},
    permissions = "document:read",
    policy = "documents.editor-or-admin")
public class SecureRouteDemoView extends Composite<Div> {

  public static final String NAV = "secure-route-demo";

  public SecureRouteDemoView() {
    H1 heading = new H1("Stil D — @SecureRoute");

    HorizontalLayout badges = new HorizontalLayout();
    Span roleBadge = new Span("ROLE_EDITOR / ROLE_ADMIN");
    roleBadge.getElement().getThemeList().add("badge error");
    Span permBadge = new Span("document:read");
    permBadge.getElement().getThemeList().add("badge success");
    Span policyBadge = new Span("documents.editor-or-admin");
    policyBadge.getElement().getThemeList().add("badge contrast");
    badges.add(roleBadge, permBadge, policyBadge);

    Paragraph description = new Paragraph(
        "This route is protected by a single @SecureRoute(roles = {ROLE_EDITOR, "
            + "ROLE_ADMIN}, permissions = document:read, policy = "
            + "documents.editor-or-admin) annotation. The starter's "
            + "SecureRouteEvaluator combines all three axes with "
            + "most-restrictive-wins semantics: only subjects that satisfy "
            + "every axis are granted. Everyone else is rerouted by the "
            + "framework. Non-Granted precedence: Unauthenticated > Forbidden "
            + "> StepUpRequired.");

    Paragraph compare = new Paragraph(
        "Compare with: DocumentsView uses one @RequiresPermission, "
            + "AdminStatusView uses one @RequiresRole, NerdView uses the "
            + "project-specific @VisibleForRoles, PolicyDemoView uses one "
            + "@RequiresPolicy. @SecureRoute is the one-liner that covers "
            + "all three axes when a route needs more than one check.");

    VerticalLayout layout = new VerticalLayout(badges, heading, description, compare);
    layout.setSpacing(false);
    layout.getThemeList().add("spacing-s");

    getContent().add(layout);
  }
}
