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
package com.svenruppert.jsentinel.accountlifecycle;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

/**
 * Account-lifecycle notification dispatcher.
 * <p>
 * {@link PasswordResetService} and {@link EmailVerificationService}
 * call {@link #send(JSentinelNotification) send(notification)} after
 * persisting a token (or marking one consumed). Implementations
 * own the transport — a mail provider adapter, an SMS gateway, an
 * audit-only log line. The {@code security-core} default is
 * {@link LoggingNotificationSender}, intentionally side-effect-free
 * so demos and tests don't accidentally reach out over the network.
 *
 * <p>Implementations must be thread-safe and
 * <strong>must not throw</strong> — a notification failure must
 * never block the lifecycle flow that emitted it. Internal failures
 * (e.g. an unreachable SMTP relay) are an implementation concern;
 * surface them via the implementation's own logging / monitoring.
 */
@ExperimentalJSentinelApi
@FunctionalInterface
public interface JSentinelNotificationSender {

  /**
   * Dispatches the notification. Must not throw.
   *
   * @param notification non-null payload
   */
  void send(JSentinelNotification notification);
}
