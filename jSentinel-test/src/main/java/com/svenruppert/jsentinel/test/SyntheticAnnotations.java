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
package com.svenruppert.jsentinel.test;

import com.svenruppert.jsentinel.authorization.annotations.RequiresAllPermissions;
import com.svenruppert.jsentinel.authorization.annotations.RequiresAnyPermission;
import com.svenruppert.jsentinel.authorization.annotations.RequiresPermission;
import com.svenruppert.jsentinel.authorization.annotations.RequiresPolicy;
import com.svenruppert.jsentinel.authorization.annotations.RequiresRole;

import java.lang.annotation.Annotation;

/**
 * Static factories for runtime-synthesised security annotations.
 * <p>
 * Useful when a test needs to drive an
 * {@code AuthorizationEvaluator.evaluate(context, annotation)} call
 * without parking a fixture class with the annotation just to read it
 * back via reflection.
 *
 * <pre>
 * new RequiresRoleEvaluator().evaluate(
 *     ctxWithSubject(admin),
 *     SyntheticAnnotations.requiresRole("ROLE_ADMIN"));
 * </pre>
 */
public final class SyntheticAnnotations {

  private SyntheticAnnotations() {
  }

  /**
   * Synthesises a {@link RequiresRole}.
   *
   * @param roles required role names
   * @return annotation
   */
  public static RequiresRole requiresRole(String... roles) {
    return new RequiresRole() {
      @Override
      public Class<? extends Annotation> annotationType() {
        return RequiresRole.class;
      }

      @Override
      public String[] value() {
        return roles;
      }
    };
  }

  /**
   * Synthesises a {@link RequiresPermission}.
   *
   * @param permissions required permission names (AND-semantics)
   * @return annotation
   */
  public static RequiresPermission requiresPermission(String... permissions) {
    return new RequiresPermission() {
      @Override
      public Class<? extends Annotation> annotationType() {
        return RequiresPermission.class;
      }

      @Override
      public String[] value() {
        return permissions;
      }
    };
  }

  /**
   * Synthesises a {@link RequiresAnyPermission}.
   *
   * @param permissions required permission names (OR-semantics)
   * @return annotation
   */
  public static RequiresAnyPermission requiresAnyPermission(String... permissions) {
    return new RequiresAnyPermission() {
      @Override
      public Class<? extends Annotation> annotationType() {
        return RequiresAnyPermission.class;
      }

      @Override
      public String[] value() {
        return permissions;
      }
    };
  }

  /**
   * Synthesises a {@link RequiresAllPermissions}.
   *
   * @param permissions required permission names (explicit AND-semantics)
   * @return annotation
   */
  public static RequiresAllPermissions requiresAllPermissions(String... permissions) {
    return new RequiresAllPermissions() {
      @Override
      public Class<? extends Annotation> annotationType() {
        return RequiresAllPermissions.class;
      }

      @Override
      public String[] value() {
        return permissions;
      }
    };
  }

  /**
   * Synthesises a {@link RequiresPolicy}.
   *
   * @param policyName required policy name
   * @return annotation
   */
  public static RequiresPolicy requiresPolicy(String policyName) {
    return new RequiresPolicy() {
      @Override
      public Class<? extends Annotation> annotationType() {
        return RequiresPolicy.class;
      }

      @Override
      public String value() {
        return policyName;
      }
    };
  }
}
