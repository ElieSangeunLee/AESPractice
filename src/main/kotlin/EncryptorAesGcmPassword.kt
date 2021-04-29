import java.nio.ByteBuffer
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec


class EncryptorAesGcmPassword {
    companion object {
        const val ENCRYPT_ALGO = "AES/GCM/NoPadding"
        const val TAG_LENGTH_BIT = 128
        const val IV_LENGTH_BYTE = 12
        const val SALT_LENGTH_BYTE = 16
        val UTF_8: Charset = StandardCharsets.UTF_8

        fun encrypt(pText: ByteArray, password: String): ByteArray {

            // 16 bytes salt
            val salt = CryptoUtils.getRandomNonce(SALT_LENGTH_BYTE)

            // GCM recommended 12 bytes iv
            val iv = CryptoUtils.getRandomNonce(IV_LENGTH_BYTE)

            // secret key from password
            val aesKeyFromPassword = CryptoUtils.getAESKeyFromPassword(password.toCharArray(), salt)
            val cipher = Cipher.getInstance(ENCRYPT_ALGO)

            // ASE-GCM needs GCMParameterSpec
            cipher.init(Cipher.ENCRYPT_MODE, aesKeyFromPassword, GCMParameterSpec(TAG_LENGTH_BIT, iv))
            val cipherText = cipher.doFinal(pText)

            // prefix IV and Salt to cipher text
            val cipherTextWithIvSalt: ByteArray = ByteBuffer.allocate(iv.size + salt.size + cipherText.size)
                .put(iv)
                .put(salt)
                .put(cipherText)
                .array()

            // string representation, base64, send this string to other for decryption.
            return cipherTextWithIvSalt
        }

        // we need the same password, salt and iv to decrypt it
        fun decrypt(cText: String, password: String): String {
            val decode = Base64.getDecoder().decode(cText.toByteArray(UTF_8))

            // get back the iv and salt from the cipher text
            val bb = ByteBuffer.wrap(decode)
            val iv = ByteArray(IV_LENGTH_BYTE)
            bb[iv]
            val salt = ByteArray(SALT_LENGTH_BYTE)
            bb[salt]
            val cipherText = ByteArray(bb.remaining())
            bb[cipherText]

            // get back the aes key from the same password and salt
            val aesKeyFromPassword = CryptoUtils.getAESKeyFromPassword(password.toCharArray(), salt)
            val cipher = Cipher.getInstance(ENCRYPT_ALGO)
            cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, GCMParameterSpec(TAG_LENGTH_BIT, iv))
            val plainText = cipher.doFinal(cipherText)
            return String(plainText, UTF_8)
        }


    }
}