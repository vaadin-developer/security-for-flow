package demo.app.views;


import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.router.Route;
import demo.app.security.roles.AuthorizationRole;
import demo.app.security.roles.VisibleFor;

@Route(NerdView.NAV)
@VisibleFor({AuthorizationRole.ADMIN, AuthorizationRole.NERD})
public class NerdView
    extends Composite<Div> {
  public static final String NAV = "nerd";


  public NerdView() {
    getContent().add(new Span("Nerd View"));
  }
}
