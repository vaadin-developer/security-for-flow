package demo.app.views;

import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.router.Route;

@Route(PublicView.NAV)
public class PublicView
    extends Composite<Div> {

  public static final String NAV = "public";

  public PublicView() {
    getContent().add(new Span("PublicView"));
  }
}
