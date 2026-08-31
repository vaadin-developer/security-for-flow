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
package eu.jsentinel.jcustos.audit;

/**
 * Single home for neutralizing attacker-influenced values before they are written into a
 * space-separated {@code key=value} log/audit line (CWE-117 log injection).
 *
 * <p>JS-SEC-045 (exit-review of JS-SEC-031 / RF09): the scrub existed as three divergent private
 * copies ({@code LoggingAuditSink}, {@code RestAccessContextFactory}, and — missing entirely —
 * {@code LoggingNotificationSender}), which drift. This is the one canonical, RF09-hardened
 * variant: it replaces every ISO control char <em>and</em> the {@code 0x20} space field-delimiter
 * with {@code '?'}, so a value can forge neither a second log line (CR/LF) nor a second
 * {@code key=value} token (space) that a whitespace-splitting SIEM would attribute elsewhere.
 * Identifiers carried in these lines (user / client / session / route / tenant) have no semantic
 * need for embedded control chars or spaces.
 */
public final class LogFieldScrubber {

  private LogFieldScrubber() {
  }

  /**
   * Replaces ISO control chars and the space delimiter in {@code value} with {@code '?'}. Only
   * allocates when a disallowed char is actually present; a {@code null} value is returned as-is.
   *
   * @param value the raw field value (may be {@code null})
   * @return the scrubbed value, safe to place into a space-separated {@code key=value} line
   */
  public static String scrub(String value) {
    if (value == null) {
      return null;
    }
    StringBuilder out = null;
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (Character.isISOControl(c) || c == ' ') {
        if (out == null) {
          out = new StringBuilder(value.length());
          out.append(value, 0, i);
        }
        out.append('?');
      } else if (out != null) {
        out.append(c);
      }
    }
    return out == null ? value : out.toString();
  }
}
