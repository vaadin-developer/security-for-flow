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
package com.svenruppert.jsentinel.session.vaadin;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.session.JSentinelVersionEnforcer;
import com.svenruppert.jsentinel.session.JSentinelVersionEnforcer.EnforcementOutcome;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterListener;
import com.vaadin.flow.router.ListenerPriority;
import com.vaadin.flow.server.VaadinSession;

import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Vaadin adapter for {@link JSentinelVersionEnforcer}.
 * <p>
 * Registered ahead of {@code AuthorizationListener} (priority
 * {@code Integer.MAX_VALUE}) so a drifted session is refused
 * before any annotation evaluation runs. Reads the per-session
 * snapshot from {@link VaadinJSentinelVersionContext}; sessions
 * without a recorded snapshot pass through untouched (the
 * application opted out by not calling
 * {@link VaadinJSentinelVersionContext#record record} after login).
 *
 * <p>On drift:
 * <ol>
 *   <li>{@link JSentinelVersionEnforcer#enforce enforce} publishes
 *       a {@code SessionStale} audit event.</li>
 *   <li>The recorded snapshot is cleared from the session.</li>
 *   <li>{@code BeforeEnterEvent#rerouteTo} sends the user to the
 *       supplied target — typically the login view.</li>
 * </ol>
 *
 * <p>The target route is supplied as a {@code Class<?>} so apps
 * keep type-safety with their {@code LoginView} subclass and so
 * the listener stays adapter-internal — there is no global
 * configuration of "the login route" here.
 */
@ExperimentalJSentinelApi
@ListenerPriority(Integer.MAX_VALUE)
public final class JSentinelVersionEnforcerListener implements BeforeEnterListener {

  private final JSentinelVersionEnforcer enforcer;
  private final Class<? extends Component> rerouteTargetOnStale;

  /**
   * @param enforcer              the adapter-neutral enforcer; non-null
   * @param rerouteTargetOnStale  navigation target for drifted sessions;
   *                              non-null. Typically the application's
   *                              {@code LoginView} subclass
   */
  public JSentinelVersionEnforcerListener(JSentinelVersionEnforcer enforcer,
                                         Class<? extends Component> rerouteTargetOnStale) {
    this.enforcer = requireNonNull(enforcer, "enforcer must not be null");
    this.rerouteTargetOnStale = requireNonNull(rerouteTargetOnStale,
        "rerouteTargetOnStale must not be null");
  }

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    Optional<VaadinJSentinelVersionContext.Snapshot> snapshotOpt =
        VaadinJSentinelVersionContext.current();
    if (snapshotOpt.isEmpty()) {
      return;
    }
    VaadinJSentinelVersionContext.Snapshot snapshot = snapshotOpt.get();
    String route = event.getNavigationTarget() == null
        ? null
        : event.getNavigationTarget().getName();
    EnforcementOutcome outcome = enforcer.enforce(
        snapshot.subjectId(),
        snapshot.tenant(),
        snapshot.snapshot(),
        snapshot.sessionId(),
        route);
    if (outcome instanceof EnforcementOutcome.SessionStale) {
      // Clear the snapshot so subsequent requests aren't re-checked
      // against the stale value while the user is on the login page.
      VaadinJSentinelVersionContext.clear(VaadinSession.getCurrent());
      event.rerouteTo(rerouteTargetOnStale);
    }
  }
}
