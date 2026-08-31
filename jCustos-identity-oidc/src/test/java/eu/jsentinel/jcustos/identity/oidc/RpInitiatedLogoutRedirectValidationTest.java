package eu.jsentinel.jcustos.identity.oidc;

/*-
 * #%L
 * jCustos OIDC — Relying-Party identity layer
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.oidc.api.LogoutRequest;
import eu.jsentinel.jcustos.oidc.api.PostLogoutRedirectValidator;

import java.net.URI;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * CWE-601: where the user lands after logout must not be decided by whoever
 * supplied the URI. The provider checks it against its registered set, but that
 * happens out of sight of this code — and if the URI came from the request, an
 * attacker picked it.
 */
@DisplayName("RpInitiatedLogoutInitiator — post_logout_redirect_uri validation (CWE-601)")
class RpInitiatedLogoutRedirectValidationTest {

  private static final URI END_SESSION = URI.create("https://op.example.test/logout");
  private static final URI ALLOWED = URI.create("https://app.example.test/bye");

  private static LogoutRequest logoutTo(URI redirect) {
    return new LogoutRequest("id-token-hint", Optional.of(redirect), Optional.empty());
  }

  @Test
  @DisplayName("an allowed target is forwarded to the provider")
  void allowedTargetPasses() {
    RpInitiatedLogoutInitiator initiator =
        new RpInitiatedLogoutInitiator(PostLogoutRedirectValidator.allowOnly(ALLOWED));

    URI logoutUri = initiator.buildLogoutUri(END_SESSION, logoutTo(ALLOWED));

    assertTrue(logoutUri.toString().contains("post_logout_redirect_uri"),
        "the redirect must survive validation: " + logoutUri);
  }

  @Test
  @DisplayName("a foreign target is refused instead of forwarded")
  void foreignTargetIsRefused() {
    RpInitiatedLogoutInitiator initiator =
        new RpInitiatedLogoutInitiator(PostLogoutRedirectValidator.allowOnly(ALLOWED));

    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
        () -> initiator.buildLogoutUri(END_SESSION,
            logoutTo(URI.create("https://attacker.test/harvest"))));

    assertTrue(ex.getMessage().contains("attacker.test"),
        "the message should name the rejected target, was: " + ex.getMessage());
  }

  @Test
  @DisplayName("a look-alike host does not pass — the classic prefix bypass")
  void lookAlikeHostIsRefused() {
    RpInitiatedLogoutInitiator initiator =
        new RpInitiatedLogoutInitiator(PostLogoutRedirectValidator.allowOnly(ALLOWED));

    // A prefix check on "https://app.example.test" would accept this.
    assertThrows(IllegalArgumentException.class,
        () -> initiator.buildLogoutUri(END_SESSION,
            logoutTo(URI.create("https://app.example.test.attacker.test/bye"))));
  }

  @Test
  @DisplayName("scheme and port are part of the identity of a target")
  void schemeAndPortMatter() {
    PostLogoutRedirectValidator validator = PostLogoutRedirectValidator.allowOnly(ALLOWED);

    assertFalse(validator.isAllowed(URI.create("http://app.example.test/bye")),
        "downgrading https to http must not pass");
    assertFalse(validator.isAllowed(URI.create("https://app.example.test:8443/bye")),
        "a different port is a different target");
    assertTrue(validator.isAllowed(URI.create("https://APP.EXAMPLE.TEST/bye")),
        "host comparison is case-insensitive, as DNS is");
  }

  @Test
  @DisplayName("query and fragment do not change the decision")
  void queryAndFragmentIgnored() {
    PostLogoutRedirectValidator validator = PostLogoutRedirectValidator.allowOnly(ALLOWED);

    assertTrue(validator.isAllowed(URI.create("https://app.example.test/bye?lang=de#top")),
        "neither carries authority over where the browser goes");
  }

  @Test
  @DisplayName("without a validator the pre-00.82 behaviour is unchanged")
  void defaultConstructorForwardsAnything() {
    RpInitiatedLogoutInitiator initiator = new RpInitiatedLogoutInitiator();

    assertDoesNotThrow(() -> initiator.buildLogoutUri(END_SESSION,
            logoutTo(URI.create("https://anywhere.test/x"))),
        "existing callers must not break on upgrade");
  }

  @Test
  @DisplayName("an empty allowlist is rejected at construction, not silently deny-all")
  void emptyAllowlistIsRejected() {
    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, PostLogoutRedirectValidator::allowOnly);

    assertTrue(ex.getMessage().contains("permitAll"),
        "the message should point at the intended alternative, was: " + ex.getMessage());
  }

  @Test
  @DisplayName("a logout without a redirect target is unaffected")
  void noRedirectNoValidation() {
    RpInitiatedLogoutInitiator initiator =
        new RpInitiatedLogoutInitiator(PostLogoutRedirectValidator.allowOnly(ALLOWED));

    URI logoutUri = initiator.buildLogoutUri(END_SESSION,
        new LogoutRequest("hint", Optional.empty(), Optional.empty()));

    assertEquals(-1, logoutUri.toString().indexOf("post_logout_redirect_uri"),
        "nothing to validate, nothing to add");
  }
}
