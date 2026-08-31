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
package eu.jsentinel.jcustos.authorization.annotations;

import eu.jsentinel.jcustos.authorization.api.AccessEvaluator;
import eu.jsentinel.jcustos.authorization.api.AuthorizationEvaluator;

import java.lang.annotation.*;

/**
 * This annotation is to be placed on other annotations, marking them as restriction-annotations and
 * assigning evaluator classes to them. Existing Vaadin-oriented annotations may use
 * {@link AccessEvaluator}; adapter-neutral annotations may use {@link AuthorizationEvaluator}.
 * Take for example the case that a certain route-target is only to be accessed by users that have
 * the role 'administrator'. Now the first step would be to create an annotation called VisibleTo
 * and annotate it with JCustosAnnotation.
 *
 * <pre>
 *     &#064;Retention(RUNTIME)
 *     &#064;JCustosAnnotation(RoleBasedAccessEvaluator.class)
 *     public &#064;interface VisibleTo {
 *         UserRoleDescription value();
 *     }
 * </pre>
 * <p>
 * The RoleBasedAccessEvaluator is an {@link AccessEvaluator} that could look something like the
 * following. Note that the generic type for this AccessEvaluator is the type of the annotation and
 * the annotation is the last parameter of {@code evaluate}.
 *
 * <pre>
 * class RoleBasedAccessEvaluator implements AccessEvaluator&lt;VisibleTo&gt; {
 *
 *     Supplier&lt;UserRoleDescription&gt; userRoleProvider;
 *
 *     &#064;Override
 *     public AccessDecision evaluate(AccessContext context, VisibleTo annotation) {
 *         final boolean hasRole = annotation.value().equals(userRoleProvider.get());
 *
 *         return hasRole ? AccessDecision.granted()
 *                        : AccessDecision.deniedWithError(UserNotInRoleException.class, null);
 *     }
 * }
 * </pre>
 * <p>
 * VisibleTo can then be used to prevent users that don't have the required role to enter the
 * route-target by just annotating the respective class
 *
 * <pre>
 *     &#064;Route("adminview")
 *     &#064;VisibleTo(UserRole.Admin)
 *     public class AdminView extends Div {
 * }
 * </pre>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.ANNOTATION_TYPE)
public @interface JCustosAnnotation {
  /**
   * The evaluator class that is to be assigned to the annotation.
   *
   * @return the evaluator class
   */
  Class<?> value();
}
