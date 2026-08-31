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
package eu.jsentinel.jcustos.identity.oidc;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;

import eu.jsentinel.jcustos.authorization.annotations.JCustosAnnotation;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires an OIDC-authenticated subject (V00.78). Optionally requires a minimum
 * authentication-context class ({@code acr}); when the present {@code acr} is not
 * among {@link #acrValues()} the evaluator returns
 * {@link eu.jsentinel.jcustos.authorization.api.AuthorizationDecision.StepUpRequired}
 * with a method derived from the requested acr (hardware / MFA / strong), tying the
 * jCustos step-up semantics (V00.70/V00.72) to OIDC {@code acr_values}. Bound to
 * {@link OidcAuthenticatedEvaluator} via {@link JCustosAnnotation} and discovered
 * by the V00.70 annotation scanner.
 *
 * @since 00.78.00
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({TYPE, METHOD})
@JCustosAnnotation(OidcAuthenticatedEvaluator.class)
public @interface OidcAuthenticated {

  /** The acceptable {@code acr} values; empty means "any authenticated subject". */
  String[] acrValues() default {};
}
