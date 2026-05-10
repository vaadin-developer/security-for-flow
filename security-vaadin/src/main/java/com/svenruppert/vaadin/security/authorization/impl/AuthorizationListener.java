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
package com.svenruppert.vaadin.security.authorization.impl;

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.vaadin.security.audit.SecurityAuditEvent;
import com.svenruppert.vaadin.security.audit.SecurityAuditEventType;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.authorization.api.AccessEvaluator;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationDecision;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationEvaluator;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;
import com.svenruppert.vaadin.security.authorization.navigation.AccessDecision;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterListener;
import com.vaadin.flow.router.ListenerPriority;
import com.vaadin.flow.server.*;
import com.vaadin.flow.shared.Registration;

import java.io.Serial;
import java.io.Serializable;
import java.lang.annotation.Annotation;

import static java.util.Objects.requireNonNull;

/**
 * Vaadin adapter for the authorization phase.
 * <p>
 * This listener intercepts navigation events, delegates annotation
 * scanning to {@link SecurityAnnotationScanner}, evaluator resolution
 * to the Vaadin instantiator, and decision evaluation to
 * {@link AccessEvaluator#evaluate}. It then maps the resulting
 * {@link AccessDecision} to the {@link BeforeEnterEvent}.
 * <p>
 * Registered as a {@link VaadinServiceInitListener} via
 * {@code META-INF/services}.
 */
@ListenerPriority(Integer.MAX_VALUE - 1)
public class AuthorizationListener
    implements VaadinServiceInitListener, UIInitListener, BeforeEnterListener, HasLogger, Serializable {

  @Serial
  private static final long serialVersionUID = 974589421761348380L;

  /** Cached scanner for restriction annotations. */
  private final SecurityAnnotationScanner scanner = new SecurityAnnotationScanner();

  /** Creates core contexts from Vaadin events. */
  private final VaadinAccessContextFactory contextFactory = new VaadinAccessContextFactory();

  /** Maps core decisions back to Vaadin navigation calls. */
  private final VaadinAccessDecisionMapper decisionMapper = new VaadinAccessDecisionMapper();

  /** Creates a new instance. */
  public AuthorizationListener() {
  }

  @Override
  public void serviceInit(ServiceInitEvent event) {
    event.getSource().addUIInitListener(this);
  }

  @Override
  public void uiInit(UIInitEvent event) {
    UI ui = event.getUI();
    Registration reg = ui.addBeforeEnterListener(this);
    ui.addDetachListener(e -> reg.remove());
  }

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    Class<?> navigationTarget = event.getNavigationTarget();

    scanner.scan(navigationTarget).ifPresent(pair -> {
      // 1. Resolve evaluator via Vaadin instantiator
      Class<?> evaluatorClass = pair.evaluatorClass();
      requireNonNull(evaluatorClass,
          "AccessEvaluator class must not be null for " + navigationTarget.getName());

      Object evaluator = VaadinService.getCurrent()
          .getInstantiator()
          .getOrCreate(evaluatorClass);
      requireNonNull(evaluator,
          "Could not instantiate AccessEvaluator: " + evaluatorClass.getName());

      // 2. Evaluate — obtain a Vaadin-free decision
      Annotation annotation = pair.annotation();
      logger().info("Evaluating access for {} with {}", event.getLocation(), annotation);
      AccessContext context = contextFactory.create(event);
      AccessDecision decision = evaluate(evaluator, context, annotation);

      // 3. Audit the decision
      audit(decision, context);

      // 4. Apply the decision to the Vaadin event
      decisionMapper.apply(decision, event);
    });
  }

  private void audit(AccessDecision decision, AccessContext context) {
    SecurityAuditEventType type = decision instanceof AccessDecision.Granted
        ? SecurityAuditEventType.ACCESS_GRANTED
        : SecurityAuditEventType.ACCESS_DENIED;

    String decisionLabel = switch (decision) {
      case AccessDecision.Granted ignored -> "GRANTED";
      case AccessDecision.Reroute reroute -> "REROUTE_" + reroute.target();
      case AccessDecision.RerouteToError err -> "ERROR_" + err.type().getSimpleName();
      case AccessDecision.RerouteWithParameter<?> r -> "REROUTE_PARAM_" + r.target();
      case AccessDecision.RerouteWithParameters<?> r -> "REROUTE_PARAMS_" + r.target();
    };

    SecurityAuditService sink = SecurityServiceResolver.securityAuditService();
    try {
      sink.record(SecurityAuditEvent.builder(type)
          .route(context.resourceName())
          .decision(decisionLabel)
          .subjectId(context.subject().map(SecuritySubject::subjectId).orElse(null))
          .username(context.subject().map(SecuritySubject::displayName).orElse(null))
          .attribute("operation", context.operation())
          .build());
    } catch (RuntimeException auditFailure) {
      // never block navigation because the audit sink failed
    }
  }

  @SuppressWarnings("unchecked")
  private AccessDecision evaluate(Object evaluator, AccessContext context, Annotation annotation) {
    if (evaluator instanceof AccessEvaluator<?> accessEvaluator) {
      return ((AccessEvaluator<Annotation>) accessEvaluator).evaluate(context, annotation);
    }
    if (evaluator instanceof AuthorizationEvaluator<?> authorizationEvaluator) {
      AuthorizationDecision decision =
          ((AuthorizationEvaluator<Annotation>) authorizationEvaluator).evaluate(context, annotation);
      return map(decision);
    }
    throw new IllegalStateException(
        "Unsupported evaluator type: " + evaluator.getClass().getName());
  }

  private AccessDecision map(AuthorizationDecision decision) {
    return switch (decision) {
      case AuthorizationDecision.Granted() -> AccessDecision.granted();
      case AuthorizationDecision.Unauthenticated(String reason) -> AccessDecision.denied("login", false);
      case AuthorizationDecision.Forbidden(String reason) ->
          AccessDecision.deniedWithError(SecurityException.class, reason);
    };
  }
}
