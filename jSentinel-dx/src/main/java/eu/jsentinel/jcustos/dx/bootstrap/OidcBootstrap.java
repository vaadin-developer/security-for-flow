package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oidc.api.ClaimsToPermissionsMapper;
import eu.jsentinel.jcustos.oidc.api.ClaimsToRolesMapper;
import eu.jsentinel.jcustos.oidc.api.ClaimsToSubjectMapper;
import eu.jsentinel.jcustos.oidc.api.ClaimsToTenantMapper;
import eu.jsentinel.jcustos.oidc.api.IdTokenValidator;
import eu.jsentinel.jcustos.oidc.api.OidcDiscoveryClient;
import eu.jsentinel.jcustos.oidc.api.UserInfoClient;
import eu.jsentinel.jcustos.oidc.api.VendorProfile;

import java.net.URI;
import java.time.Duration;

/**
 * V00.78 declarative OIDC Relying-Party sub-builder, exposed via {@code .oidc(...)}
 * on {@link CommonJSentinelBootstrap}; all three adapter facades inherit it. The DX
 * layer only records + STRICT-validates the configuration (Konzept §11); the HTTP
 * clients are assembled in {@code jSentinel-identity-oidc(-*)}, so this layer stays
 * free of any JOSE / HTTP-client compile dependency (it references only the
 * JOSE-free {@code oidc/api} + {@code oauth2/api} types in {@code jSentinel-core}).
 *
 * <p>STRICT raises for {@code oidc/missing-issuer}, {@code oidc/missing-client-id},
 * {@code oidc/scope-without-openid} and {@code oidc/logout-without-post-logout-redirect-uri};
 * a non-https / non-loopback {@link #redirectUri(URI)} raises
 * {@code oidc/redirect-uri-not-https}.
 *
 * @since 00.78.00
 */
public interface OidcBootstrap {

  /** The OIDC issuer (required — STRICT raises {@code oidc/missing-issuer}). */
  OidcBootstrap issuer(String issuer);

  /** The RP {@code client_id} (required — STRICT raises {@code oidc/missing-client-id}). */
  OidcBootstrap clientId(String clientId);

  /** How the RP authenticates to the token endpoint. */
  OidcBootstrap clientAuthentication(ClientAuthentication auth);

  /** The registered redirect URI (https or http://localhost* — STRICT-checked). */
  OidcBootstrap redirectUri(URI uri);

  /** The requested scopes ({@code openid} is mandatory — STRICT-checked). */
  OidcBootstrap scope(String... scopes);

  /** Whether the {@code nonce} check is required (default true). */
  OidcBootstrap requireNonce(boolean require);

  /** The maximum acceptable authentication age ({@code max_age}). */
  OidcBootstrap maxAge(Duration maxAge);

  /** The required authentication-context classes ({@code acr_values}). */
  OidcBootstrap acrValues(String... acrValues);

  /** Whether to pull claims from the UserInfo endpoint (default false). */
  OidcBootstrap userInfoEnabled(boolean enabled);

  /** Whether RP-initiated logout is enabled (default false). */
  OidcBootstrap logoutEnabled(boolean enabled);

  /** Where the OP returns after logout (required when {@code logoutEnabled(true)}). */
  OidcBootstrap postLogoutRedirectUri(URI uri);

  /** Overrides the claims-to-subject mapper (default: the spec-clean mapper). */
  OidcBootstrap claimsMapper(ClaimsToSubjectMapper mapper);

  /** Overrides the roles mapper (default: empty). */
  OidcBootstrap rolesMapper(ClaimsToRolesMapper mapper);

  /** Overrides the permissions mapper (default: empty). */
  OidcBootstrap permissionsMapper(ClaimsToPermissionsMapper mapper);

  /** Overrides the tenant mapper (default: empty). */
  OidcBootstrap tenantMapper(ClaimsToTenantMapper mapper);

  /** Overrides the discovery client. */
  OidcBootstrap discoveryClient(OidcDiscoveryClient client);

  /** Overrides the ID-token validator. */
  OidcBootstrap idTokenValidator(IdTokenValidator validator);

  /** Overrides the UserInfo client. */
  OidcBootstrap userInfoClient(UserInfoClient client);

  /**
   * V00.79: applies a vendor profile — a bundle of IdP-specific claim mappers
   * (Keycloak {@code realm_access}, Entra {@code wids}, Auth0 namespace, …). Each
   * mapper the profile provides overrides the corresponding default; explicit
   * {@code .rolesMapper(...)} etc. calls after {@code .vendor(...)} still win.
   *
   * @param profile the vendor profile (e.g. {@code KeycloakProfile.INSTANCE})
   * @return this builder
   */
  @ExperimentalJSentinelApi
  OidcBootstrap vendor(VendorProfile profile);
}
