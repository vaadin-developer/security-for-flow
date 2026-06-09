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

import com.svenruppert.jsentinel.authorization.annotations.RequiresPolicy;
import com.svenruppert.jsentinel.demo.restclient.security.DemoPolicyInitListener;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;

/**
 * Stil A6 — admission via {@link RequiresPolicy} that emits
 * {@code StepUpRequired}.
 *
 * <p>The {@code sensitive.requires-mfa} policy is registered at
 * service init by
 * {@link DemoPolicyInitListener#POLICY_SENSITIVE_REQUIRES_MFA};
 * it unconditionally returns {@code StepUpRequired(MFA)}. The
 * Vaadin {@code AuthorizationListener} reroutes the navigation to
 * the route returned by
 * {@code JSentinelServiceResolver.stepUpRouteName()} — i.e. to
 * {@link StepUpChallengeView}. A user navigating to this URL will
 * never actually see this view; they always land on the challenge
 * page instead.
 */
@Route(StepUpDemoView.NAV)
@RequiresPolicy(DemoPolicyInitListener.POLICY_SENSITIVE_REQUIRES_MFA)
public class StepUpDemoView extends Composite<Div> {

  public static final String NAV = "step-up-demo";

  public StepUpDemoView() {
    VerticalLayout layout = new VerticalLayout();
    layout.add(new H1("Sensitive operation (you should never reach this)"));
    layout.add(new Paragraph(
        "If you can read this, the AuthorizationListener did NOT reroute "
            + "you to the step-up challenge. That's a wiring regression."));
    getContent().add(layout);
  }
}
