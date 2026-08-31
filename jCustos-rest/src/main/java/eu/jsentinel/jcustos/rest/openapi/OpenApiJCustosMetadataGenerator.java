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
package eu.jsentinel.jcustos.rest.openapi;

import eu.jsentinel.jcustos.authorization.annotations.RequiresAllPermissions;
import eu.jsentinel.jcustos.authorization.annotations.RequiresAnyPermission;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPolicy;
import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Extracts security-annotation metadata from a REST handler class
 * so applications can render an OpenAPI {@code security} section
 * without re-implementing annotation introspection.
 * <p>
 * Reads the five framework-supplied annotations from
 * {@code authorization.annotations}:
 * <ul>
 *   <li>{@link RequiresPermission} → {@link JCustosRequirement.Scheme#PERMISSION}
 *       with {@link JCustosRequirement.Operator#ALL}.</li>
 *   <li>{@link RequiresAllPermissions} → same as above (alias).</li>
 *   <li>{@link RequiresAnyPermission} → {@code PERMISSION} +
 *       {@link JCustosRequirement.Operator#ANY}.</li>
 *   <li>{@link RequiresRole} → {@link JCustosRequirement.Scheme#ROLE}
 *       with {@code ALL}.</li>
 *   <li>{@link RequiresPolicy} → {@link JCustosRequirement.Scheme#POLICY}
 *       with {@code ALL}.</li>
 * </ul>
 *
 * <p>Custom application annotations (annotated with
 * {@code @JCustosAnnotation}) are <strong>not</strong> exported —
 * their semantics are app-specific and the generator has no way to
 * translate them. Apps that want them in the OpenAPI export run
 * their own pass over the handler classes and merge with this
 * generator's output.
 *
 * <p>The generator is stateless and thread-safe.
 */
@ExperimentalJCustosApi
public final class OpenApiJCustosMetadataGenerator {

  /** Default constructor. */
  public OpenApiJCustosMetadataGenerator() {
  }

  /**
   * Runs the extraction.
   *
   * @param handlerClass REST handler class; non-null
   * @return metadata block; never {@code null} (may be
   *         {@link HandlerJCustosMetadata#isEmpty() empty} for
   *         classes that carry no framework security annotations)
   */
  public HandlerJCustosMetadata generate(Class<?> handlerClass) {
    requireNonNull(handlerClass, "handlerClass must not be null");
    List<JCustosRequirement> classLevel = extract(handlerClass);
    Map<String, List<JCustosRequirement>> methods = new LinkedHashMap<>();
    for (Method method : handlerClass.getDeclaredMethods()) {
      if (method.isSynthetic() || method.isBridge()) {
        continue;
      }
      if (Modifier.isStatic(method.getModifiers())) {
        continue;
      }
      List<JCustosRequirement> reqs = extract(method);
      if (!reqs.isEmpty()) {
        methods.put(method.getName(), reqs);
      }
    }
    return new HandlerJCustosMetadata(handlerClass.getName(), classLevel, methods);
  }

  private List<JCustosRequirement> extract(AnnotatedElement element) {
    List<JCustosRequirement> out = new ArrayList<>(4);
    RequiresPermission rp = element.getAnnotation(RequiresPermission.class);
    if (rp != null) {
      out.add(new JCustosRequirement(
          JCustosRequirement.Scheme.PERMISSION,
          JCustosRequirement.Operator.ALL,
          Arrays.asList(rp.value())));
    }
    RequiresAllPermissions rap = element.getAnnotation(RequiresAllPermissions.class);
    if (rap != null) {
      out.add(new JCustosRequirement(
          JCustosRequirement.Scheme.PERMISSION,
          JCustosRequirement.Operator.ALL,
          Arrays.asList(rap.value())));
    }
    RequiresAnyPermission rany = element.getAnnotation(RequiresAnyPermission.class);
    if (rany != null) {
      out.add(new JCustosRequirement(
          JCustosRequirement.Scheme.PERMISSION,
          JCustosRequirement.Operator.ANY,
          Arrays.asList(rany.value())));
    }
    RequiresRole rr = element.getAnnotation(RequiresRole.class);
    if (rr != null) {
      out.add(new JCustosRequirement(
          JCustosRequirement.Scheme.ROLE,
          JCustosRequirement.Operator.ALL,
          Arrays.asList(rr.value())));
    }
    RequiresPolicy rpol = element.getAnnotation(RequiresPolicy.class);
    if (rpol != null) {
      out.add(new JCustosRequirement(
          JCustosRequirement.Scheme.POLICY,
          JCustosRequirement.Operator.ALL,
          Arrays.asList(rpol.value())));
    }
    return List.copyOf(out);
  }
}
