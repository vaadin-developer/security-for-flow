package eu.jsentinel.jcustos.demo.skill.vaadin.views;

import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.router.Route;

import java.util.Optional;

/**
 * Conditionally renders a "Home" navigation button for a view.
 *
 * <p>Rule shared by every skill-generated view: a view that lives
 * inside a Router Layout (e.g. {@code AppLayout}) already has a
 * drawer / navbar pointing back to {@link PublicHomeView} — adding another
 * Home button would be redundant. A view registered as a top-level
 * {@code @Route} without a layout has no such fallback, so this
 * helper hands it one.
 *
 * <p>The decision reads {@code @Route(layout = ...)}: Vaadin's
 * default of {@link UI}{@code .class} means "no parent layout
 * configured". Any other value means the view is embedded and the
 * helper returns {@link Optional#empty()}.
 *
 * <h2>Usage</h2>
 * <pre>
 *   HorizontalLayout toolbar = new HorizontalLayout();
 *   HomeButton.forStandalone(getClass()).ifPresent(toolbar::add);
 * </pre>
 *
 * <p>For views without a toolbar (e.g. subclasses of the framework's
 * {@code SessionManagementView}), drop the button into the root
 * layout instead:
 * <pre>
 *   HomeButton.forStandalone(getClass())
 *       .ifPresent(btn -&gt; getContent().addComponentAsFirst(btn));
 * </pre>
 */
public final class HomeButton {

  private HomeButton() {
  }

  /**
   * Returns a Home button when {@code viewClass} is registered as a
   * standalone {@code @Route} (no parent layout). Otherwise returns
   * {@link Optional#empty()}.
   *
   * @param viewClass the view class to inspect; usually
   *                  {@code getClass()} from the calling view
   * @return populated optional iff the view is standalone
   */
  public static Optional<Button> forStandalone(Class<?> viewClass) {
    Route route = viewClass.getAnnotation(Route.class);
    if (route == null || !UI.class.equals(route.layout())) {
      return Optional.empty();
    }
    Button btn = new Button("Home", VaadinIcon.HOME.create(),
        e -> UI.getCurrent().navigate(PublicHomeView.class));
    btn.addThemeVariants(ButtonVariant.LUMO_TERTIARY);
    return Optional.of(btn);
  }
}
