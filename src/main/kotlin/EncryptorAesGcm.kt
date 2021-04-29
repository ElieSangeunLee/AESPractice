import java.nio.ByteBuffer
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class EncryptorAesGcm {
    companion object {
        const val ENCRYPT_ALGO = "AES/GCM/NoPadding"
        const val TAG_LENGTH_BIT = 128
        const val IV_LENGTH_BYTE = 12
        const val AES_KEY_BIT = 256
        val UTF_8: Charset = StandardCharsets.UTF_8

        // AES-GCM needs GCMParameterSpec
        fun encrypt(pText: ByteArray, secret: SecretKey, iv: ByteArray): ByteArray {
            val cipher = Cipher.getInstance(ENCRYPT_ALGO)
            cipher.init(Cipher.ENCRYPT_MODE, secret, GCMParameterSpec(TAG_LENGTH_BIT, iv))
            return cipher.doFinal(pText)
        }

        // prefix IV length + IV bytes to cipher text
        fun encryptWithPrefixIV(pText: ByteArray, secret: SecretKey, iv: ByteArray): ByteArray {
            val cipherText = encrypt(pText, secret, iv)
            return ByteBuffer.allocate(iv.size + cipherText.size)
                .put(iv)
                .put(cipherText)
                .array()
        }

        fun decrypt(cText: ByteArray, secret: SecretKey, iv: ByteArray): String {
            val cipher = Cipher.getInstance(ENCRYPT_ALGO)
            cipher.init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(TAG_LENGTH_BIT, iv))
            val plainText = cipher.doFinal(cText)
            return String(plainText, UTF_8)
        }

        fun decryptWithPrefixIV(cText: ByteArray, secret: SecretKey): String {
            val bb = ByteBuffer.wrap(cText)
            val iv = ByteArray(IV_LENGTH_BYTE)
            bb[iv]
            //bb.get(iv, 0, iv.length);
            val cipherText = ByteArray(bb.remaining())
            bb[cipherText]
            return decrypt(cipherText, secret, iv)
        }

    }
}