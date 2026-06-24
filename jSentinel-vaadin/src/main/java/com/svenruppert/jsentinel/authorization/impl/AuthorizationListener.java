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
package com.svenruppert.jsentinel.authorization.impl;

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.jsentinel.audit.AccessDenied;
import com.svenruppert.jsentinel.audit.AccessGranted;
import com.svenruppert.jsentinel.audit.AuditEvent;
import com.svenruppert.jsentinel.audit.JSentinelAuditService;
import com.svenruppert.jsentinel.audit.StepUpChallenged;
import com.svenruppert.jsentinel.authorization.api.AccessEvaluator;
import com.svenruppert.jsentinel.authorization.api.AuthorizationDecision;
import com.svenruppert.jsentinel.authorization.api.AuthorizationEvaluator;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.authorization.navigation.AccessContext;
import com.svenruppert.jsentinel.authorization.navigation.AccessDecision;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterListener;
import com.vaadin.flow.router.ListenerPriority;
import com.vaadin.flow.server.*;
import com.vaadin.flow.shared.Registration;

import java.io.Serial;
import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Vaadin adapter for the authorization phase.
 * <p>
 * This listener intercepts navigation events, delegates annotation
 * scanning to {@link JSentinelAnnotationScanner}, evaluator resolution
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
  private final JSentinelAnnotationScanner scanner = new JSentinelAnnotationScanner();

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

      // 2. Evaluate — obtain a Vaadin-free decision plus the original
      //    AuthorizationDecision (when the evaluator produced one), so
      //    audit can record StepUp specifics that get lost in the
      //    AccessDecision mapping.
      Annotation annotation = pair.annotation();
      logger().info("Evaluating access for {} with {}", event.getLocation(), annotation);
      AccessContext context = contextFactory.create(event);
      EvaluatedDecision evaluated = evaluateWithOriginal(evaluator, context, annotation);

      // 3. Audit the decision
      audit(evaluated, context);

      // 4. Apply the decision to the Vaadin event
      decisionMapper.apply(evaluated.mapped(), event);
    });
  }

  /**
   * Internal result of running an evaluator: the {@link AccessDecision}
   * that drives navigation, plus the original {@link AuthorizationDecision}
   * if the evaluator produced one (legacy {@link AccessEvaluator}s
   * return only an {@code AccessDecision}, so {@code original} is
   * empty in that branch).
   */
  record EvaluatedDecision(AccessDecision mapped, Optional<AuthorizationDecision> original) {
  }

  private void audit(EvaluatedDecision evaluated, AccessContext context) {
    String subjectId = context.subject().map(JSentinelSubject::subjectId).orElse(null);
    String route = context.resourceName();
    Instant now = Instant.now(Clock.systemUTC());

    AccessDecision decision = evaluated.mapped();
    AuditEvent event;
    if (decision instanceof AccessDecision.Granted) {
      event = new AccessGranted(now, subjectId, route);
    } else {
      String reason = originalReasonIfApplicable(evaluated)
          .orElseGet(() -> switch (decision) {
            case AccessDecision.Granted ignored -> "Granted";
            case AccessDecision.Reroute reroute -> "Reroute:" + reroute.target();
            case AccessDecision.RerouteToError err -> "Error:" + err.type().getSimpleName();
            case AccessDecision.RerouteWithParameter<?> r -> "ReroutePARAM:" + r.target();
            case AccessDecision.RerouteWithParameters<?> r -> "ReroutePARAMS:" + r.target();
          });
      event = new AccessDenied(now, subjectId, route, reason);
    }

    JSentinelAuditService sink = JSentinelServiceResolver.securityAuditService();
    try {
      sink.publish(event);
    } catch (RuntimeException auditFailure) {
      // never block navigation because the audit sink failed
    }

    // Emit a structured StepUpChallenged event alongside the coarse
    // AccessDenied. Mirrors the REST adapter; audit consumers can
    // pivot on method/reason without parsing the AccessDenied.reason
    // string.
    evaluated.original()
        .filter(AuthorizationDecision.StepUpRequired.class::isInstance)
        .map(AuthorizationDecision.StepUpRequired.class::cast)
        .ifPresent(stepUp -> {
          try {
            sink.publish(new StepUpChallenged(
                now, subjectId, route, stepUp.method(), stepUp.reason()));
          } catch (RuntimeException auditFailure) {
            // never block navigation because the audit sink failed
          }
        });
  }

  /**
   * Derives the audit reason from the original {@link AuthorizationDecision}
   * when the evaluator produced one. For {@code StepUpRequired} this is the
   * structured {@code StepUpRequired:<method>[:<reason>]} string; for
   * {@code Forbidden} it is {@code Forbidden[:<reason>]} — the evaluator's
   * internal reason is preserved <em>here, in the audit channel only</em>, even
   * though it is deliberately withheld from the user-facing error view (R018).
   * Returns {@link Optional#empty()} for every other shape (and for legacy
   * {@link AccessEvaluator}s, which carry no original) so the caller falls back
   * to the {@link AccessDecision}-based reason.
   */
  private static Optional<String> originalReasonIfApplicable(EvaluatedDecision evaluated) {
    return evaluated.original().flatMap(original -> switch (original) {
      case AuthorizationDecision.StepUpRequired stepUp ->
          Optional.of("StepUpRequired:" + stepUp.method()
              + (stepUp.reason().isEmpty() ? "" : ":" + stepUp.reason()));
      case AuthorizationDecision.Forbidden(String reason) ->
          Optional.of(reason.isEmpty() ? "Forbidden" : "Forbidden:" + reason);
      default -> Optional.empty();
    });
  }

  @SuppressWarnings("unchecked")
  private EvaluatedDecision evaluateWithOriginal(
      Object evaluator, AccessContext context, Annotation annotation) {
    if (evaluator instanceof AccessEvaluator<?> accessEvaluator) {
      return new EvaluatedDecision(
          ((AccessEvaluator<Annotation>) accessEvaluator).evaluate(context, annotation),
          Optional.empty());
    }
    if (evaluator instanceof AuthorizationEvaluator<?> authorizationEvaluator) {
      AuthorizationDecision decision =
          ((AuthorizationEvaluator<Annotation>) authorizationEvaluator).evaluate(context, annotation);
      return new EvaluatedDecision(map(decision), Optional.of(decision));
    }
    throw new IllegalStateException(
        "Unsupported evaluator type: " + evaluator.getClass().getName());
  }

  /**
   * Legacy helper kept for test reflection — delegates to
   * {@link #evaluateWithOriginal} and discards the original. New
   * callers should use {@link #evaluateWithOriginal} so audit can
   * surface step-up specifics.
   */
  @SuppressWarnings("unchecked")
  private AccessDecision evaluate(Object evaluator, AccessContext context, Annotation annotation) {
    return evaluateWithOriginal(evaluator, context, annotation).mapped();
  }

  private AccessDecision map(AuthorizationDecision decision) {
    return switch (decision) {
      case AuthorizationDecision.Granted() -> AccessDecision.granted();
      case AuthorizationDecision.Unauthenticated(String _) ->
          // R025: resolve the login route through JSentinelServiceResolver
          // (default "login") instead of a hardcoded literal, so apps that name
          // their login route differently are not silently broken.
          AccessDecision.denied(JSentinelServiceResolver.loginRouteName(), false);
      case AuthorizationDecision.Forbidden(String _) ->
          // R018: never surface the evaluator's internal reason to the user-facing
          // error view (it may carry subject ids, policy names, SQL). Use a generic
          // message, mirroring the REST adapter's generic "Forbidden" body; the real
          // reason is recorded only in the audit channel (see audit()).
          AccessDecision.deniedWithError(SecurityException.class, "Access denied");
      case AuthorizationDecision.StepUpRequired stepUp ->
          // Reroute to the configured step-up route — the consuming
          // application registers a Route under that name to render
          // the MFA / re-auth challenge.
          AccessDecision.reroute(JSentinelServiceResolver.stepUpRouteName(), false);
    };
  }
}
