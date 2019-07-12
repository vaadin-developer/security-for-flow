package demo.app.views;

import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.router.Route;
import demo.app.security.roles.AuthorizationRole;
import demo.app.security.roles.VisibleFor;

@Route(AdminView.NAV)
@VisibleFor({AuthorizationRole.ADMIN})
public class AdminView
    extends Composite<Div> {
  public static final String NAV = "admin";

  public AdminView() {
    getContent().add(new Span("AdminView"));
  }
}
