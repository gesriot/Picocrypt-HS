package io.github.picocrypt_ng.picocrypt_ng

import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction

/**
 * Encodes this CharArray to UTF-8 bytes without ever creating a String (which
 * would be an immutable, un-zeroable JVM object that survives in heap dumps).
 * The transient backing buffer is zeroed before returning. The returned array
 * is owned by the caller and must be zeroed after use.
 *
 * The encoder replaces malformed/unmappable input instead of throwing, so this
 * never raises CharacterCodingException and the caller's Result contract holds.
 */
internal fun CharArray.toUtf8BytesSecure(): ByteArray {
    val charBuffer = CharBuffer.wrap(this)
    val byteBuffer = Charsets.UTF_8.newEncoder()
        .onMalformedInput(CodingErrorAction.REPLACE)
        .onUnmappableCharacter(CodingErrorAction.REPLACE)
        .encode(charBuffer)
    val out = ByteArray(byteBuffer.remaining())
    byteBuffer.get(out)
    if (byteBuffer.hasArray()) byteBuffer.array().fill(0)
    return out
}
