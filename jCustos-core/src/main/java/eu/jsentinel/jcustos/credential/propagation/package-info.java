/**
 * V00.74 declarative token-propagation SPIs.
 *
 * <p>This package owns the four building blocks every downstream V00.74
 * module composes:
 * <ul>
 *   <li>{@link eu.jsentinel.jcustos.credential.propagation.TokenCredential}
 *       — sealed type for inbound / outbound tokens.</li>
 *   <li>{@code TokenCredentialStore} — per-subject store the runtime and
 *       compile-time wrappers read.</li>
 *   <li>{@code OutboundTokenStrategy} — pluggable "how does this token
 *       reach the downstream call" SPI.</li>
 *   <li>{@code PassThroughStrategy} — the core default.</li>
 * </ul>
 *
 * <p>Every public type in this package is <strong>stable</strong> as of
 * V00.83. The surface shipped in V00.74 and was promoted once the demo
 * adoption it was waiting for actually landed: the
 * {@code demo-jcustos-vaadin-rest-client} backend gateway is a
 * {@code @PropagateToken} interface whose calls carry no token parameter
 * and name no {@code Authorization} header. Signatures did not change to
 * accommodate it.
 *
 * <p><strong>Discipline:</strong> {@code TokenCredential#value()} is the raw
 * token. It is never logged, never persisted, never audited. Every record
 * subtype masks the value in {@code toString()}. The same discipline applies
 * to the V00.71 {@code PasswordHash} surface — see Konzept-V00.71 §1.
 *
 * @since 00.74.00
 */
package eu.jsentinel.jcustos.credential.propagation;
