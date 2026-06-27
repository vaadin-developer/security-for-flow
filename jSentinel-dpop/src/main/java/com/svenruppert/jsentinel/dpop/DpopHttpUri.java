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
package com.svenruppert.jsentinel.dpop;

import java.net.URI;
import java.util.Locale;

/**
 * Normalises an HTTP URI to its DPoP {@code htu} form (RFC 9449 §4.3 step 9): the
 * scheme + authority + path, with the query and fragment removed. Scheme and host are
 * lower-cased; the default port for the scheme is dropped so {@code https://h:443/p}
 * and {@code https://h/p} compare equal.
 */
final class DpopHttpUri {

  private DpopHttpUri() {
  }

  static String normalize(URI uri) {
    String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
    String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
    int port = uri.getPort();
    if (isDefaultPort(scheme, port)) {
      port = -1;
    }
    String path = uri.getPath() == null ? "" : uri.getPath();
    StringBuilder sb = new StringBuilder();
    sb.append(scheme).append("://").append(host);
    if (port != -1) {
      sb.append(':').append(port);
    }
    sb.append(path);
    return sb.toString();
  }

  private static boolean isDefaultPort(String scheme, int port) {
    return ("https".equals(scheme) && port == 443) || ("http".equals(scheme) && port == 80);
  }
}
