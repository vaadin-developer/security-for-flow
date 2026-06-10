/**
 * V00.74 declarative token-propagation SPIs.
 *
 * <p>This package owns the four building blocks every downstream V00.74
 * module composes:
 * <ul>
 *   <li>{@link com.svenruppert.jsentinel.credential.propagation.TokenCredential}
 *       — sealed type for inbound / outbound tokens.</li>
 *   <li>{@code TokenCredentialStore} — per-subject store the runtime and
 *       compile-time wrappers read.</li>
 *   <li>{@code OutboundTokenStrategy} — pluggable "how does this token
 *       reach the downstream call" SPI.</li>
 *   <li>{@code PassThroughStrategy} — the core default.</li>
 * </ul>
 *
 * <p>Every public type in this package is annotated
 * {@link com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi}.
 * V00.74 ships the surface; stable-API promotion is staged for V00.76 after
 * at least one real demo adoption.
 *
 * <p><strong>Discipline:</strong> {@code TokenCredential#value()} is the raw
 * token. It is never logged, never persisted, never audited. Every record
 * subtype masks the value in {@code toString()}. The same discipline applies
 * to the V00.71 {@code PasswordHash} surface — see Konzept-V00.71 §1.
 *
 * @since 00.74.00
 */
package com.svenruppert.jsentinel.credential.propagation;
