package eu.jsentinel.jcustos.demo.skill.vaadin;

import com.vaadin.flow.component.page.AppShellConfigurator;
import com.vaadin.flow.component.page.Push;

/**
 * Vaadin app shell. The jCustos wiring runs once at Vaadin service
 * init in {@code security.bootstrap.JCustosBootstrapInitListener},
 * registered via {@code META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener}.
 */
@Push
public class Application implements AppShellConfigurator {
}
