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
package eu.jsentinel.jcustos.authorization.navigation;

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
public record NavigationJCustosContext(
    Class<?> navigationTarget,
    boolean restricted,
    boolean subjectAvailable,
    boolean isLoginTarget
) {
}
