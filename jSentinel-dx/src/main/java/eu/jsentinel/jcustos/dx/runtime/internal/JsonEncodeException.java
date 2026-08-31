/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
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
package eu.jsentinel.jcustos.dx.runtime.internal;

/**
 * Boundary-check throwable for {@link JsonEncoder}. Lives in the
 * {@code eu.jsentinel.jcustos.dx.runtime.internal} package — by
 * convention, classes in {@code internal} packages are <strong>not</strong>
 * part of the public API surface.
 * {@code JCustosRuntime#toJson()} only ever encodes the deterministic
 * {@code toMap()} output, so this exception fires only on a framework
 * bug, never on consumer input.
 *
 * @since 00.74.10
 */
public final class JsonEncodeException extends RuntimeException {

  JsonEncodeException(String message) {
    super(message);
  }
}
