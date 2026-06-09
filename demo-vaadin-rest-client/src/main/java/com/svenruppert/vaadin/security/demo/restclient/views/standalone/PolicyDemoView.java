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

import com.svenruppert.vaadin.security.authorization.annotations.RequiresPolicy;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import com.svenruppert.vaadin.security.demo.restclient.backend.RemoteUser;
import com.svenruppert.vaadin.security.demo.restclient.security.ClientJSentinelContext;
import com.svenruppert.vaadin.security.demo.restclient.security.DemoPolicyInitListener;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Pre;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;

/**
 * Stil A4 — admission via {@link RequiresPolicy}.
 *
 * <p>The demo policy {@code documents.editor-or-admin} is registered
 * at service init by {@link DemoPolicyInitListener}. The framework's
 * {@code AuthorizationListener} resolves the annotation, looks up the
 * policy through {@code JSentinelServiceResolver.policyRegistry()}, and
 * reroutes anyone who does not satisfy the rule. Users that reach this
 * view passed the policy.
 */
@Route(PolicyDemoView.NAV)
@RequiresPolicy(DemoPolicyInitListener.POLICY_EDITOR_OR_ADMIN)
public class PolicyDemoView extends Composite<Div> {

  public static final String NAV = "policy-demo";

  public PolicyDemoView() {
    VerticalLayout layout = new VerticalLayout();
    layout.add(new H1("Policy demo (Stil A4 — @RequiresPolicy)"));
    layout.add(new Paragraph(
        "Policies combine multiple authorisation predicates in a single "
            + "named rule. They are the right tool when the admission "
            + "condition cannot be expressed by either @RequiresRole or "
            + "@RequiresPermission alone."));

    layout.add(new H2("Rule registered at service init"));
    Pre rule = new Pre("""
        Policy.named("documents.editor-or-admin")
            .allowIf(SubjectPredicates.hasAnyRole("ROLE_ADMIN", "ROLE_EDITOR"))
            .orIf(SubjectPredicates.hasPermission("document:write"))
            .deny("must be ADMIN/EDITOR or hold document:write")
            .build();""");
    layout.add(rule);

    layout.add(new H2("How you got in"));
    layout.add(currentUserSummary());

    layout.add(new H2("Try the negative case"));
    layout.add(new Paragraph(
        "Sign out, log in as a Viewer (role-only, no document:write "
            + "permission). The Vaadin AuthorizationListener will catch "
            + "the @RequiresPolicy annotation, evaluate the registered "
            + "policy, and reroute to an error view because none of the "
            + "allow-predicates match."));

    getContent().add(layout);
  }

  private static Paragraph currentUserSummary() {
    RemoteUser user = ClientJSentinelContext.user().orElse(null);
    if (user == null) {
      return new Paragraph(
          "(no cached user) — this should not happen on a protected route.");
    }
    String roles = user.roles().stream().map(RoleName::value).sorted().toList().toString();
    String permissions = user.permissions().stream()
        .map(PermissionName::value).sorted().toList().toString();
    return new Paragraph(
        "Subject: " + user.displayName()
            + " — roles=" + roles
            + " permissions=" + permissions);
  }
}