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
package eu.jsentinel.jcustos.browserless;

import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonTester;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Proof-of-concept for Vaadin's {@code browserless-test-junit6}.
 * <p>
 * Validates that the testing infrastructure is wired in this project:
 * navigate to a test-only fixture route, locate components via
 * {@code $view(...)}, click a button via the typed
 * {@link ButtonTester}, and observe the side effect. No bootstrap,
 * no authentication, no session policies — just the
 * {@link BrowserlessTest} runtime.
 * <p>
 * Real adapter tests (login flow, lockout banner, B3 rotation,
 * {@code /audit}-grid) will live in {@code demo-vaadin} where the
 * concrete views are registered as routes. This smoke test only
 * proves that {@code BrowserlessTest} works in the security-vaadin
 * module so future test-only fixtures (e.g. a stub
 * {@code LoginView}) can run here as well.
 */
@DisplayName("BrowserlessTest — smoke test")
class BrowserlessSmokeTest extends BrowserlessTest {

  @Test
  @DisplayName("navigate + locate + click cycle through the BrowserlessTest API")
  void clickIncrementsLabel() {
    SmokeFixtureView view = navigate(SmokeFixtureView.class);

    assertNotNull(view, "navigate(...) must return the rendered view");
    assertEquals("0", $view(Span.class).id("counter").getText(),
        "fixture starts at 0");

    ButtonTester<Button> button = test($view(Button.class).id("increment"));
    button.click();
    button.click();
    button.click();

    assertEquals("3", $view(Span.class).id("counter").getText(),
        "three clicks must produce 3");
  }

  /** Test-only route — counts button clicks into a {@link Span}. */
  @Route("browserless-smoke")
  public static class SmokeFixtureView extends Composite<VerticalLayout> {

    private int count = 0;
    private final Span counter = new Span("0") {{ setId("counter"); }};

    public SmokeFixtureView() {
      VerticalLayout root = getContent();
      root.add(new H1("Smoke fixture"));
      root.add(counter);
      Button increment = new Button("Increment");
      increment.setId("increment");
      increment.addClickListener(e -> {
        count++;
        counter.setText(Integer.toString(count));
      });
      root.add(increment);
    }
  }
}
