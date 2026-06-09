/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package com.svenruppert.jsentinel.credential.secret;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * Short-lived container for password / pepper / token material.
 *
 * <h2>Lifecycle</h2>
 * <p>{@code SecretValue} is {@link AutoCloseable} so callers can scope
 * a secret to a try-with-resources block. The {@link #close()} hook
 * calls {@link #destroy()}, which overwrites the internal {@code char[]}
 * with zeros. Once destroyed, every accessor throws
 * {@link IllegalStateException} (CWE-226).</p>
 *
 * <h2>JVM memory honesty</h2>
 * <p>The JVM offers no perfect way to scrub heap memory: garbage
 * collection may have copied the backing array to other regions before
 * destruction; strings produced by an unrelated caller may keep a copy
 * elsewhere. {@code SecretValue} provides best-effort defence: it owns
 * the backing array, never converts to {@link String} internally, and
 * zeros temporary UTF-8 buffers it constructs. Callers should still
 * keep secret lifetimes as short as possible.</p>
 *
 * <h2>Interoperability</h2>
 * <p>Phase 1a/1b providers accept {@code char[]} for historical reasons.
 * {@link #asChars()} returns a defensive copy the caller owns; they
 * remain responsible for zeroing it after use. The package also exposes
 * {@link #asUtf8Bytes()} for providers that need a {@code byte[]}
 * (bcrypt, scrypt). Both methods refuse access after destruction.</p>
 */
public final class SecretValue implements AutoCloseable {

  private final char[] chars;
  private volatile boolean destroyed;

  private SecretValue(char[] chars) {
    this.chars = chars;
  }

  /**
   * Builds a {@code SecretValue} from a caller-owned {@code char[]}.
   * The caller's array is defensively copied; the original array
   * remains the caller's responsibility (and is typically zeroed
   * immediately afterwards).
   */
  public static SecretValue ofChars(char[] source) {
    Objects.requireNonNull(source, "source");
    char[] copy = new char[source.length];
    System.arraycopy(source, 0, copy, 0, source.length);
    return new SecretValue(copy);
  }

  /**
   * Convenience overload for {@link String} inputs. Note that
   * {@code String} instances are immutable and may be retained by the
   * JVM string pool; prefer {@link #ofChars(char[])} for genuinely
   * sensitive material.
   */
  public static SecretValue ofString(String source) {
    Objects.requireNonNull(source, "source");
    return ofChars(source.toCharArray());
  }

  /**
   * Number of characters held. Reported even after destruction so
   * callers can debug lifecycle issues without recovering the value.
   */
  public int length() {
    return chars.length;
  }

  /**
   * Whether {@link #destroy()} has been called.
   */
  public boolean isDestroyed() {
    return destroyed;
  }

  /**
   * Returns a defensive copy of the held characters. The caller owns
   * the returned array and should zero it after use.
   *
   * @throws IllegalStateException if the secret was already destroyed
   */
  public char[] asChars() {
    requireAlive();
    char[] copy = new char[chars.length];
    System.arraycopy(chars, 0, copy, 0, chars.length);
    return copy;
  }

  /**
   * Returns the UTF-8 encoding of the held characters in a fresh byte
   * array. The internal {@link CharBuffer} and intermediate
   * {@link ByteBuffer} backing array are zeroed before returning.
   *
   * @throws IllegalStateException if the secret was already destroyed
   */
  public byte[] asUtf8Bytes() {
    requireAlive();
    CharBuffer charBuffer = CharBuffer.wrap(chars);
    ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(charBuffer);
    byte[] copy = new byte[byteBuffer.remaining()];
    byteBuffer.get(copy);
    if (byteBuffer.hasArray()) {
      Arrays.fill(byteBuffer.array(),
          byteBuffer.arrayOffset(),
          byteBuffer.arrayOffset() + byteBuffer.capacity(), (byte) 0);
    }
    return copy;
  }

  /**
   * Zeros the internal storage. Subsequent accessor calls throw
   * {@link IllegalStateException}. Calling {@code destroy} on an
   * already-destroyed secret is a no-op.
   */
  public void destroy() {
    if (!destroyed) {
      Arrays.fill(chars, '\0');
      destroyed = true;
    }
  }

  /**
   * Alias for {@link #destroy()} so {@code SecretValue} can be used in
   * try-with-resources blocks.
   */
  @Override
  public void close() {
    destroy();
  }

  /**
   * Returns a redacted shape: {@code "SecretValue[length=N, destroyed=false]"}.
   * Never contains the held material (CWE-209 / CWE-312).
   */
  @Override
  public String toString() {
    return "SecretValue[length=" + chars.length + ", destroyed=" + destroyed + "]";
  }

  private void requireAlive() {
    if (destroyed) {
      throw new IllegalStateException("SecretValue has been destroyed");
    }
  }
}
