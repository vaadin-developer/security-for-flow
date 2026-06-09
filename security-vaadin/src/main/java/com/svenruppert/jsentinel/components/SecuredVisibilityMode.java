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
package com.svenruppert.jsentinel.components;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

/**
 * How a secured component reacts when the current subject is not
 * permitted.
 *
 * <ul>
 *   <li>{@link #HIDE} — set the component invisible. Standard
 *       affordance for menu items and links where the affordance
 *       itself should disappear.</li>
 *   <li>{@link #DISABLE} — keep the component visible but disable
 *       it. Standard affordance for primary buttons where the
 *       absence would be confusing ("why is this gone?").</li>
 * </ul>
 *
 * <p>Either mode is purely a UI affordance — the server-side guard
 * still has to enforce the permission on every action invocation.
 * Hiding a button does not protect against a hand-crafted RPC call.
 */
@ExperimentalJSentinelApi
public enum SecuredVisibilityMode {
  HIDE,
  DISABLE
}
