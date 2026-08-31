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
package eu.jsentinel.jcustos.demo.skill.vaadin.security.oidc;

import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.dx.bootstrap.OidcBootstrap;
import eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinJCustosBootstrap;
import eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinSecurity;
import eu.jsentinel.jcustos.identity.vendor.auth0.Auth0Profile;
import eu.jsentinel.jcustos.identity.vendor.entra.EntraProfile;
import eu.jsentinel.jcustos.identity.vendor.keycloak.KeycloakProfile;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oidc.api.VendorProfile;

import java.net.URI;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * V00.79.20 B9 — reference wiring for an OIDC Relying Party against the three most
 * common IdPs via their {@link VendorProfile}. One line per vendor selects the
 * IdP-specific claim mappers (Keycloak realm/resource roles, Entra wids/roles/groups +
 * tid tenant, Auth0 namespaced claims); everything else (discovery, JWKS rotation,
 * ID-token validation, auth-code + PKCE) is identical.
 *
 * <p>This class is a compile-checked example of the public vendor-profile API — it does
 * not auto-run (a live login needs a real IdP). The demo's default login stays
 * username/password; call {@link #configure} from your own init when you have a provider.
 */
public final class VendorProfileOidcExample {

  /** The vendors this demo shows a one-line profile for. */
  public enum Idp {
    KEYCLOAK, ENTRA, AUTH0;
  }

  private VendorProfileOidcExample() {
  }

  private static VendorProfile profileFor(Idp idp) {
    return switch (idp) {
      case KEYCLOAK -> KeycloakProfile.INSTANCE;
      case ENTRA -> EntraProfile.INSTANCE;
      case AUTH0 -> Auth0Profile.INSTANCE;
    };
  }

  /**
   * The {@code .oidc(...)} recording lambda for {@code idp}: issuer + client + redirect +
   * scopes + the vendor profile. An explicit {@code .rolesMapper(...)} after
   * {@code .vendor(...)} would still win.
   */
  public static Consumer<OidcBootstrap> wiring(
      Idp idp, String issuer, String clientId, String clientSecret, URI redirectUri) {
    Objects.requireNonNull(idp, "idp");
    Objects.requireNonNull(issuer, "issuer");
    Objects.requireNonNull(clientId, "clientId");
    Objects.requireNonNull(clientSecret, "clientSecret");
    Objects.requireNonNull(redirectUri, "redirectUri");
    VendorProfile profile = profileFor(idp);
    return o -> o
        .issuer(issuer)
        .clientId(clientId)
        .clientAuthentication(new ClientAuthentication.ClientSecretBasic(
            clientId, SecretValue.ofString(clientSecret)))
        .redirectUri(redirectUri)
        .scope("openid", "profile", "email")
        .vendor(profile);
  }

  /**
   * Builds (but does not {@code install()}) a Vaadin bootstrap with the vendor OIDC
   * profile recorded — so the caller decides when/whether to install against a live IdP.
   */
  public static VaadinJCustosBootstrap configure(
      Idp idp, String issuer, String clientId, String clientSecret, URI redirectUri) {
    return VaadinSecurity.bootstrap()
        .oidc(wiring(idp, issuer, clientId, clientSecret, redirectUri));
  }
}
