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
package eu.jsentinel.jcustos.oauth2;

/*-
 * #%L
 * jCustos OAuth2 — RP flows (token endpoint, auth-code, refresh, device)
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.oauth2.api.DeviceAuthorizationResponse;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oauth2.api.TokenEndpointClient;
import eu.jsentinel.jcustos.oauth2.api.TokenResponse;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Drives the RFC 8628 §3.4/§3.5 device-grant polling loop (V00.77): repeatedly
 * exchanges the {@code device_code} at the token endpoint until the human
 * authorizes, the code expires or the AS denies it. It honours the server's
 * minimum {@code interval}, applies the mandated +5 s back-off on
 * {@code slow_down}, treats {@code authorization_pending} as "keep waiting", and
 * maps {@code access_denied} / {@code expired_token} to the matching
 * {@link OAuth2Error}. The {@link Sleeper} + clock are injected so the loop is
 * driven in real time in production and deterministically under test.
 */
public final class DeviceTokenPoller {

  /** RFC 8628 §3.5: extra seconds added to the interval on every {@code slow_down}. */
  private static final long SLOW_DOWN_INCREMENT_SECONDS = 5L;

  /** Time abstraction so the poll cadence is real in production, instant under test. */
  @FunctionalInterface
  public interface Sleeper {
    void sleep(Duration duration) throws InterruptedException;

    /** A sleeper backed by {@link Thread#sleep(long)}. */
    static Sleeper realTime() {
      return duration -> Thread.sleep(Math.max(0L, duration.toMillis()));
    }
  }

  private final TokenEndpointClient tokenClient;
  private final Sleeper sleeper;
  private final Supplier<Instant> clock;

  public DeviceTokenPoller(TokenEndpointClient tokenClient) {
    this(tokenClient, Sleeper.realTime(), Instant::now);
  }

  public DeviceTokenPoller(TokenEndpointClient tokenClient, Sleeper sleeper, Supplier<Instant> clock) {
    this.tokenClient = Objects.requireNonNull(tokenClient, "tokenClient");
    this.sleeper = Objects.requireNonNull(sleeper, "sleeper");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Polls until the device grant resolves.
   *
   * @param device the device-authorization response to poll for
   * @return the obtained tokens, or {@link OAuth2Error.AuthorizationDenied} /
   *         {@link OAuth2Error.DeviceCodeExpired} / the propagated transport error
   */
  public Result<TokenResponse, OAuth2Error> poll(DeviceAuthorizationResponse device) {
    Objects.requireNonNull(device, "device");
    // R-EXIT-2: floor the interval to >= 1s so a hostile/buggy AS returning
    // interval=0 cannot turn the poll into a tight busy-loop hammering the endpoint.
    long intervalSeconds = Math.max(1L, device.intervalSeconds());
    while (true) {
      if (clock.get().isAfter(device.expiresAt())) {
        return Result.failure(new OAuth2Error.DeviceCodeExpired());
      }
      try {
        sleeper.sleep(Duration.ofSeconds(intervalSeconds));
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return Result.failure(new OAuth2Error.NetworkError("interrupted"));
      }

      Result<TokenResponse, OAuth2Error> result = tokenClient.deviceToken(device.deviceCode());
      if (result.isSuccess()) {
        return result;
      }
      OAuth2Error error = result.fold(ok -> (OAuth2Error) null, e -> e);
      if (!(error instanceof OAuth2Error.ProtocolError protocol)) {
        return result; // network / endpoint / malformed — propagate verbatim
      }
      switch (protocol.oauthError()) {
        case "authorization_pending" -> { /* keep waiting */ }
        case "slow_down" -> intervalSeconds += SLOW_DOWN_INCREMENT_SECONDS;
        case "access_denied" -> {
          return Result.failure(new OAuth2Error.AuthorizationDenied("access_denied"));
        }
        case "expired_token" -> {
          return Result.failure(new OAuth2Error.DeviceCodeExpired());
        }
        default -> {
          return result; // an unexpected protocol error ends the loop
        }
      }
    }
  }
}
