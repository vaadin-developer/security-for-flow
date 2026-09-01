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
package eu.jsentinel.jcustos.authorization.api;

import java.lang.annotation.*;

/**
 * Marks a type or method as part of the experimental security API.
 *
 * <p>Experimental APIs may change in incompatible ways or be removed in
 * future releases without a deprecation period. Anything <em>not</em>
 * carrying this marker is covered by the project's SemVer commitments:
 * interfaces grow only through {@code default} methods, records and enums
 * only additively, and annotations only through elements with defaults.
 *
 * <p>The marker means one of two different things, and the distinction
 * matters when deciding whether to depend on something:
 *
 * <ul>
 *   <li><strong>Still soaking.</strong> The surface is expected to become
 *       stable once it has been carried by at least three minor releases
 *       and exercised by a real integration. This is the common case.</li>
 *   <li><strong>A design position.</strong> The permission-based access API
 *       carries the marker not because it is new but because role-based
 *       access is the recommended path for production use. Its
 *       {@link #value()} text says so.</li>
 * </ul>
 *
 * <p>Read {@link #value()} where it is set — it distinguishes the two.
 *
 * <p>Promotion is a pure annotation removal with no behavioural change, so
 * it never breaks a compiling caller. The reverse is a SemVer regression;
 * {@code StableApiPromotionGuardTest} exists to catch it.
 *
 * <p>On an otherwise-stable type, this marker may sit on an individual
 * method — that is how a stable surface exposes a type that is still
 * soaking, rather than holding the whole surface back. See
 * {@code OidcBootstrap#vendor(VendorProfile)}.
 *
 * <p>The per-release inventory of what was promoted and what was
 * deliberately kept lives in the release notes, most recently
 * {@code RELEASE-NOTES-00.83.00.md}.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD})
public @interface ExperimentalJCustosApi {

  /**
   * Description of the experimental nature.
   *
   * @return the description
   */
  String value() default "This API is experimental and may change without notice.";
}
