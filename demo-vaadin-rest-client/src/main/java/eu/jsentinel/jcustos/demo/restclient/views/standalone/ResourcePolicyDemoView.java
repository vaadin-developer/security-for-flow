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
package eu.jsentinel.jcustos.demo.restclient.views.standalone;

import eu.jsentinel.jcustos.audit.PolicyEvaluated;
import eu.jsentinel.jcustos.audit.JSentinelAuditService;
import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JSentinelSubject;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.demo.restclient.backend.RemoteUser;
import eu.jsentinel.jcustos.demo.restclient.security.ClientJSentinelContext;
import eu.jsentinel.jcustos.demo.restclient.security.DemoPolicyInitListener;
import eu.jsentinel.jcustos.demo.restclient.security.resource.DemoDocument;
import eu.jsentinel.jcustos.demo.restclient.security.resource.DemoDocumentStore;
import eu.jsentinel.jcustos.demo.restclient.security.resource.DemoDocumentResolver;
import eu.jsentinel.jcustos.policy.api.PolicyContext;
import eu.jsentinel.jcustos.policy.api.PolicyDecision;
import eu.jsentinel.jcustos.policy.api.ResourceRef;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Pre;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Stil A5 — resource-based admission via the Policy API.
 *
 * <p>The {@code document.owner-or-admin} policy is registered at
 * service init by {@link DemoPolicyInitListener}; it combines
 * {@code SubjectPredicates.hasRole("ROLE_ADMIN")} with
 * {@code ResourcePredicates.ownerMatchesSubject("document", "ownerId")}.
 * Each row below triggers a programmatic policy evaluation against
 * the framework's {@code PolicyRegistry}, passing a
 * {@link ResourceRef} that the
 * {@link DemoDocumentResolver} resolves into an {@code ownerId}
 * attribute. The decision is shown as a notification and emitted as
 * a {@link PolicyEvaluated} audit event visible in the AuditView.
 *
 * <p>This view itself is open to every authenticated role — the
 * resource-based filtering is performed per click, not per route.
 */
@Route(ResourcePolicyDemoView.NAV)
@RequiresRole({"ROLE_ADMIN", "ROLE_EDITOR", "ROLE_VIEWER"})
public class ResourcePolicyDemoView extends Composite<Div> {

  public static final String NAV = "resource-policy-demo";

  public ResourcePolicyDemoView() {
    VerticalLayout layout = new VerticalLayout();
    layout.add(new H1("Resource-based policy demo (Stil A5)"));
    layout.add(new Paragraph(
        "Per-click programmatic policy evaluation against a ResourceRef "
            + "the DemoDocumentResolver knows how to dereference. Admin "
            + "reaches every document; everyone else reaches only the "
            + "documents whose ownerId matches their subjectId."));

    layout.add(new H2("Rule registered at service init"));
    layout.add(new Pre("""
        Policy.named("document.owner-or-admin")
            .allowIf(SubjectPredicates.hasRole("ROLE_ADMIN"))
            .orIf(ResourcePredicates.ownerMatchesSubject("document", "ownerId"))
            .deny("must be ADMIN or document owner")
            .build();"""));

    layout.add(new H2("Documents"));
    DemoDocumentStore.all().forEach(doc -> layout.add(documentRow(doc)));

    getContent().add(layout);
  }

  private static Component documentRow(DemoDocument doc) {
    Span title = new Span(doc.title());
    Span owner = new Span(" — owner: " + doc.ownerId());
    owner.getStyle().set("color", "var(--lumo-secondary-text-color)");

    Button tryEdit = new Button("Try edit", event -> attemptEdit(doc));
    tryEdit.addThemeVariants(ButtonVariant.LUMO_TERTIARY, ButtonVariant.LUMO_SMALL);

    HorizontalLayout row = new HorizontalLayout(tryEdit, title, owner);
    row.setAlignItems(FlexComponent.Alignment.CENTER);
    return row;
  }

  private static void attemptEdit(DemoDocument doc) {
    PolicyContext policyContext = buildPolicyContext(doc.id());
    PolicyDecision decision = JSentinelServiceResolver.policyRegistry()
        .evaluate(DemoPolicyInitListener.POLICY_DOCUMENT_OWNER_OR_ADMIN, policyContext);
    publishAudit(decision, policyContext);
    showNotification(doc, decision);
  }

  private static PolicyContext buildPolicyContext(String docId) {
    Optional<JSentinelSubject> subject = currentJSentinelSubject();
    ResourceRef ref = new ResourceRef(DemoDocumentResolver.RESOURCE_TYPE, docId);
    AccessContext access = new AccessContext(
        subject,
        "vaadin-button",
        "edit-document",
        "edit",
        Map.of(ResourceRef.ATTRIBUTE_KEY, ref));
    return new PolicyContext(
        access,
        DemoPolicyInitListener.POLICY_DOCUMENT_OWNER_OR_ADMIN,
        ref);
  }

  private static Optional<JSentinelSubject> currentJSentinelSubject() {
    return ClientJSentinelContext.user().map(ResourcePolicyDemoView::toJSentinelSubject);
  }

  private static JSentinelSubject toJSentinelSubject(RemoteUser user) {
    return new JSentinelSubject(
        user.subjectId(),
        user.displayName(),
        Set.copyOf(user.roles()),
        Set.copyOf(user.permissions()));
  }

  private static void publishAudit(PolicyDecision decision, PolicyContext context) {
    JSentinelAuditService sink = JSentinelServiceResolver.securityAuditService();
    String subjectId = context.subject().map(JSentinelSubject::subjectId).orElse(null);
    String label = switch (decision) {
      case PolicyDecision.Allowed ignored -> "Allowed";
      case PolicyDecision.Denied ignored -> "Denied";
      case PolicyDecision.StepUpRequired ignored -> "StepUpRequired";
    };
    String reason = switch (decision) {
      case PolicyDecision.Allowed allowed -> allowed.reason();
      case PolicyDecision.Denied denied -> denied.reason();
      case PolicyDecision.StepUpRequired stepUp ->
          stepUp.method().name() + (stepUp.reason().isEmpty() ? "" : ":" + stepUp.reason());
    };
    try {
      sink.publish(new PolicyEvaluated(
          Instant.now(Clock.systemUTC()),
          subjectId,
          context.policyName(),
          label,
          reason));
    } catch (RuntimeException ignored) {
      // audit failure must not affect the demo flow
    }
  }

  private static void showNotification(DemoDocument doc, PolicyDecision decision) {
    String message = switch (decision) {
      case PolicyDecision.Allowed allowed ->
          "Allowed: " + doc.title() + " (" + allowed.reason() + ")";
      case PolicyDecision.Denied denied ->
          "Denied: " + doc.title() + " — " + denied.reason();
      case PolicyDecision.StepUpRequired stepUp ->
          "Step-up required (" + stepUp.method() + "): " + doc.title();
    };
    Notification notification = Notification.show(message, 4000, Notification.Position.TOP_CENTER);
    if (decision instanceof PolicyDecision.Denied
        || decision instanceof PolicyDecision.StepUpRequired) {
      notification.addThemeVariants(
          com.vaadin.flow.component.notification.NotificationVariant.LUMO_ERROR);
    } else {
      notification.addThemeVariants(
          com.vaadin.flow.component.notification.NotificationVariant.LUMO_SUCCESS);
    }
  }
}
