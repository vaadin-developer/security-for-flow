package eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.session.JSentinelVersionEnforcer;
import eu.jsentinel.jcustos.session.JSentinelVersionStore;
import eu.jsentinel.jcustos.session.vaadin.JSentinelVersionEnforcerListener;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.UIInitListener;
import com.vaadin.flow.server.VaadinServiceInitListener;
import com.vaadin.flow.shared.Registration;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.MyLoginView;

import java.util.Optional;

/**
 * Registers {@link JSentinelVersionEnforcerListener} on every UI so
 * drifted sessions reroute to {@link MyLoginView}.
 *
 * <p>The listener only fires when the {@code LoginView} captured a
 * {@link eu.jsentinel.jcustos.session.JSentinelVersion} snapshot
 * at login time — which itself requires both an SPI-registered
 * {@link JSentinelVersionStore} and a
 * {@link eu.jsentinel.jcustos.authorization.api.SubjectIdResolver}.
 * Both are registered alongside this listener by the hardening skill.
 *
 * <p>Without an SPI-registered store this initialiser logs a warning
 * and skips registration — the app still runs, but with drift
 * detection silently disabled.
 *
 * <p>Registered via
 * {@code META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener}.
 */
public class JSentinelVersionInitListener
    implements VaadinServiceInitListener, HasLogger {

  @Override
  public void serviceInit(ServiceInitEvent event) {
    Optional<JSentinelVersionStore> storeOpt =
        JSentinelServiceResolver.findJSentinelVersionStore();
    if (storeOpt.isEmpty()) {
      logger().warn("JSentinelVersionStore SPI not registered — "
          + "Phase 4c drift detection disabled");
      return;
    }
    JSentinelVersionEnforcer enforcer = new JSentinelVersionEnforcer(
        storeOpt.get(), JSentinelServiceResolver.securityAuditService());
    event.getSource().addUIInitListener((UIInitListener) uiInitEvent -> {
      JSentinelVersionEnforcerListener listener =
          new JSentinelVersionEnforcerListener(enforcer, MyLoginView.class);
      Registration reg = uiInitEvent.getUI().addBeforeEnterListener(listener);
      uiInitEvent.getUI().addDetachListener(detach -> reg.remove());
    });
  }
}
