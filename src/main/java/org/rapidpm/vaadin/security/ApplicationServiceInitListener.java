package org.rapidpm.vaadin.security;

import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.server.ErrorHandler;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.UIInitListener;
import com.vaadin.flow.server.VaadinServiceInitListener;
import com.vaadin.flow.shared.Registration;
import org.rapidpm.dependencies.core.logger.HasLogger;
import org.rapidpm.vaadin.security.authorization.LoginListener;
import org.rapidpm.vaadin.security.authorization.LoginListenerProvider;

public class ApplicationServiceInitListener
    implements VaadinServiceInitListener, HasLogger {

  private Registration loginRegistration;

  @Override
  public void serviceInit(ServiceInitEvent e) {
    e.getSource()
     .addUIInitListener((UIInitListener) uiInitEvent -> {
       UI ui = uiInitEvent.getUI();
       logger().info("init LoginListener for .. " + ui.getRouter());

       final LoginListener loginListener = new LoginListenerProvider().load();
       loginRegistration = ui.addBeforeEnterListener(loginListener);

       ui.getSession()
         .setErrorHandler((ErrorHandler) errorEvent -> {
           logger().warning("Uncaught UI exception", errorEvent.getThrowable());
           Notification.show("We are sorry, but an internal error occurred");
         });
     });
  }
}
