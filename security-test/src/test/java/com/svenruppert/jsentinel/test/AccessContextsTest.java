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

import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.authorization.navigation.AccessContext;
import com.svenruppert.jsentinel.policy.api.ResourceRef;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AccessContextsTest {

  @Test
  @DisplayName("anonymous() has no subject and default surface")
  void anonymous() {
    AccessContext ctx = AccessContexts.anonymous();
    assertTrue(ctx.subject().isEmpty());
    assertEquals(AccessContexts.DEFAULT_RESOURCE_TYPE, ctx.resourceType());
    assertEquals(AccessContexts.DEFAULT_RESOURCE_NAME, ctx.resourceName());
    assertEquals(AccessContexts.DEFAULT_OPERATION, ctx.operation());
    assertTrue(ctx.attributes().isEmpty());
  }

  @Test
  @DisplayName("withSubject binds the subject")
  void withSubject() {
    JSentinelSubject subject = JSentinelSubjects.anonymousIdentity("u-1");
    AccessContext ctx = AccessContexts.withSubject(subject);
    assertSame(subject, ctx.subject().orElseThrow());
    assertTrue(ctx.attributes().isEmpty());
  }

  @Test
  @DisplayName("withSubjectAndResource stashes the ResourceRef under ATTRIBUTE_KEY")
  void withSubjectAndResource() {
    JSentinelSubject subject = JSentinelSubjects.anonymousIdentity("u-1");
    ResourceRef ref = new ResourceRef("document", "42");
    AccessContext ctx = AccessContexts.withSubjectAndResource(subject, ref);

    assertSame(subject, ctx.subject().orElseThrow());
    assertSame(ref, ctx.attributes().get(ResourceRef.ATTRIBUTE_KEY));
  }

  @Test
  @DisplayName("anonymousWithResource stashes the ResourceRef without a subject")
  void anonymousWithResource() {
    ResourceRef ref = new ResourceRef("document", "42");
    AccessContext ctx = AccessContexts.anonymousWithResource(ref);

    assertTrue(ctx.subject().isEmpty());
    assertSame(ref, ctx.attributes().get(ResourceRef.ATTRIBUTE_KEY));
  }
}
