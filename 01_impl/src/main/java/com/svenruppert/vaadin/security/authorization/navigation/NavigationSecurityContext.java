/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.svenruppert.vaadin.security.authorization.navigation;

/**
 * Vaadin-free context for making navigation security decisions.
 * <p>
 * This record captures the relevant facts about a navigation event
 * without depending on any Vaadin types. The Vaadin listener builds
 * this context from the {@code BeforeEnterEvent} and passes it to
 * {@link NavigationAccessDecisionService}.
 *
 * @param navigationTarget the class being navigated to
 * @param restricted       whether the target carries a restriction annotation
 * @param subjectAvailable whether a security subject exists in the current session
 * @param isLoginTarget    whether the target is the login view itself
 */
public record NavigationSecurityContext(
    Class<?> navigationTarget,
    boolean restricted,
    boolean subjectAvailable,
    boolean isLoginTarget
) {
}
