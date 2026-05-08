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
package com.svenruppert.vaadin.security.authorization;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("LoginListeners")
class LoginListenersTest {

  @AfterEach
  void tearDown() {
    LoginListeners.reset();
  }

  @Test
  @DisplayName("multiple LoginListener implementations fail explicitly")
  void multipleLoginListeners_throwWithMessage() {
    var ex = assertThrows(IllegalStateException.class,
        () -> LoginListeners.requireSingleService(
            String.class,
            List.of("first", "second")));

    assertTrue(ex.getMessage().contains("multiple implementations"));
    assertTrue(ex.getMessage().contains(String.class.getName()));
    assertTrue(ex.getMessage().contains("java.lang.String"));
  }

  @Test
  @DisplayName("findSingleService returns the single registered entry")
  void findSingleService_singleEntry() {
    Optional<String> result = LoginListeners.findSingleService(
        String.class, List.of("only"));

    assertTrue(result.isPresent());
    assertEquals("only", result.get());
  }

  @Test
  @DisplayName("findSingleService returns empty for an empty iterable")
  void findSingleService_empty() {
    Optional<String> result = LoginListeners.findSingleService(
        String.class, List.of());

    assertTrue(result.isEmpty());
  }

  @Test
  @DisplayName("findSingleService throws when more than one entry is present")
  void findSingleService_multiple() {
    assertThrows(IllegalStateException.class,
        () -> LoginListeners.findSingleService(
            String.class, List.of("first", "second", "third")));
  }

  @Test
  @DisplayName("requireSingleService returns the single registered entry")
  void requireSingleService_singleEntry() {
    String resolved = LoginListeners.requireSingleService(
        String.class, List.of("only"));

    assertSame("only", resolved);
  }

  @Test
  @DisplayName("requireSingleService throws actionable error when no entry is registered")
  void requireSingleService_emptyMessage() {
    var ex = assertThrows(IllegalStateException.class,
        () -> LoginListeners.requireSingleService(
            String.class, List.of()));

    assertTrue(ex.getMessage().contains("no implementation found"),
        "missing-service error must explain the cause");
    assertTrue(ex.getMessage().contains(String.class.getName()));
    assertTrue(ex.getMessage().contains("META-INF/services"),
        "missing-service error must point operators at META-INF/services");
    assertTrue(ex.getMessage().contains("ServiceLoader"),
        "missing-service error must mention ServiceLoader");
  }

  @Test
  @DisplayName("loginListener() throws actionable error message when no SPI is registered")
  void loginListener_missingSpi_throws() {
    var ex = assertThrows(IllegalStateException.class,
        LoginListeners::loginListener);

    assertTrue(ex.getMessage().contains("LoginListener"));
    assertTrue(ex.getMessage().contains("META-INF/services"));
  }

  @Test
  @DisplayName("findLoginListener() returns empty when no SPI is registered")
  void findLoginListener_missingSpi_empty() {
    assertTrue(LoginListeners.findLoginListener().isEmpty());
  }

  @Test
  @DisplayName("multipleServices error message lists every implementation class")
  void multipleServices_listsAllImplementations() {
    var ex = assertThrows(IllegalStateException.class,
        () -> LoginListeners.requireSingleService(
            CharSequence.class, List.of("first", new StringBuilder("second"))));

    assertTrue(ex.getMessage().contains(String.class.getName()),
        "first impl class must appear in error");
    assertTrue(ex.getMessage().contains(StringBuilder.class.getName()),
        "second impl class must appear in error");
    assertTrue(ex.getMessage().contains("classpath-order"),
        "the warning about classpath-order dependent behavior must remain");
  }

  @Test
  @DisplayName("reset is idempotent")
  void reset_isIdempotent() {
    LoginListeners.reset();
    LoginListeners.reset();
    assertTrue(LoginListeners.findLoginListener().isEmpty());
  }
}
