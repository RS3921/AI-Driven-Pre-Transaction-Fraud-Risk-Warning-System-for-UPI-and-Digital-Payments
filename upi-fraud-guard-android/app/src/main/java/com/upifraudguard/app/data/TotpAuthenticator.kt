package com.upifraudguard.app.data

import android.net.Uri
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** RFC 6238 TOTP compatible with Google Authenticator (SHA-1, 6 digits, 30 seconds). */
object TotpAuthenticator {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private const val STEP_SECONDS = 30L

    fun newSecret(): String {
        val bytes = ByteArray(20).also(SecureRandom()::nextBytes)
        return encodeBase32(bytes)
    }

    fun provisioningUri(secret: String, email: String): String =
        "otpauth://totp/UPI%20Fraud%20Guard:${Uri.encode(email.trim())}?secret=$secret&issuer=UPI%20Fraud%20Guard&algorithm=SHA1&digits=6&period=30"

    fun verify(secret: String, code: String, nowMillis: Long = System.currentTimeMillis()): Boolean {
        val digits = code.filter(Char::isDigit)
        if (digits.length != 6 || secret.isBlank()) return false
        val currentStep = nowMillis / 1000 / STEP_SECONDS
        return (-1L..1L).any { offset -> generate(secret, currentStep + offset) == digits }
    }

    private fun generate(secret: String, step: Long): String {
        val key = decodeBase32(secret)
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(key, "HmacSHA1"))
        val hash = mac.doFinal(ByteBuffer.allocate(8).putLong(step).array())
        val offset = hash.last().toInt() and 0x0f
        val binary = ((hash[offset].toInt() and 0x7f) shl 24) or
            ((hash[offset + 1].toInt() and 0xff) shl 16) or
            ((hash[offset + 2].toInt() and 0xff) shl 8) or
            (hash[offset + 3].toInt() and 0xff)
        return (binary % 1_000_000).toString().padStart(6, '0')
    }

    private fun encodeBase32(input: ByteArray): String {
        val output = StringBuilder()
        var buffer = 0
        var bitsLeft = 0
        input.forEach { byte ->
            buffer = (buffer shl 8) or (byte.toInt() and 0xff)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                output.append(ALPHABET[(buffer shr (bitsLeft - 5)) and 31])
                bitsLeft -= 5
            }
        }
        if (bitsLeft > 0) output.append(ALPHABET[(buffer shl (5 - bitsLeft)) and 31])
        return output.toString()
    }

    private fun decodeBase32(value: String): ByteArray {
        val clean = value.uppercase().filter { it in ALPHABET }
        val output = ArrayList<Byte>()
        var buffer = 0
        var bitsLeft = 0
        clean.forEach { char ->
            buffer = (buffer shl 5) or ALPHABET.indexOf(char)
            bitsLeft += 5
            if (bitsLeft >= 8) {
                output += ((buffer shr (bitsLeft - 8)) and 0xff).toByte()
                bitsLeft -= 8
            }
        }
        return output.toByteArray()
    }
}
