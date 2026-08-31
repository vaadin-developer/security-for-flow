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

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.TYPE;

/**
 * Compile-time trigger for the {@code security-processor} annotation
 * processor. Marks a concrete class (not an interface) for which an
 * auto-generated {@code <Type>Secured} wrapper subclass shall be emitted
 * during compilation. The generated wrapper overrides every public,
 * non-final, non-static method of the original and inserts a
 * {@link eu.jsentinel.jcustos.authorization.api.JSentinelEnforcer}
 * call ahead of the {@code super.<method>(...)} delegate when the method
 * (or the class) carries one of the method-security annotations:
 *
 * <ul>
 *   <li>{@link RequiresRole}</li>
 *   <li>{@link RequiresPermission}</li>
 *   <li>{@link RequiresAnyPermission}</li>
 *   <li>{@link RequiresAllPermissions}</li>
 *   <li>{@link RequiresPolicy}</li>
 * </ul>
 *
 * <p>This annotation itself does <strong>not</strong> trigger
 * runtime enforcement and carries no {@link JSentinelAnnotation}
 * meta-binding. It is consumed at compile time only — retention is
 * {@link RetentionPolicy#SOURCE} so the marker does not appear in
 * the class file.
 *
 * <p>For runtime-only enforcement via {@code java.lang.reflect.Proxy}
 * (interfaces) use
 * {@code eu.jsentinel.jcustos.standalone.SecuredProxy.wrap(...)}
 * instead — that path requires neither this annotation nor the
 * annotation processor.
 *
 * <p>Constraints checked by the annotation processor:
 * <ul>
 *   <li>The annotated type must not be {@code final} (the wrapper
 *       extends it).</li>
 *   <li>Methods to be guarded must be {@code public}, non-final and
 *       non-static. Method-security annotations on {@code final},
 *       {@code private} or {@code static} methods raise a compile
 *       error.</li>
 *   <li>{@link Object} methods ({@code equals}, {@code hashCode},
 *       {@code toString}, {@code finalize}) are not wrapped.</li>
 * </ul>
 */
@Retention(RetentionPolicy.SOURCE)
@Target(TYPE)
public @interface Secured {
}
