import java.nio.ByteBuffer
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec


class EncryptorAesGcmPasswordFile {
    companion object {
        const val ENCRYPT_ALGO = "AES/GCM/NoPadding"
        const val TAG_LENGTH_BIT = 128
        const val IV_LENGTH_BYTE = 12
        const val SALT_LENGTH_BYTE = 16
        val UTF_8: Charset = StandardCharsets.UTF_8

        fun encryptFile(fromFile: String, toFile: String, password: String) {

            // read a normal txt file
            val fileContent = Files.readAllBytes(Paths.get(ClassLoader.getSystemResource(fromFile).toURI()))

            // encrypt with a password
            val encryptedText: ByteArray = encrypt(fileContent, password)

            // save a file
            val path = Paths.get(toFile)
            Files.write(path, encryptedText)
        }

        private fun encrypt(pText: ByteArray, password: String): ByteArray {
            // 16 bytes salt
            // 16 bytes salt
            val salt = CryptoUtils.getRandomNonce(SALT_LENGTH_BYTE)

            // GCM recommended 12 bytes iv?

            // GCM recommended 12 bytes iv?
            val iv = CryptoUtils.getRandomNonce(IV_LENGTH_BYTE)

            // secret key from password

            // secret key from password
            val aesKeyFromPassword = CryptoUtils.getAESKeyFromPassword(password.toCharArray(), salt)

            val cipher = Cipher.getInstance(ENCRYPT_ALGO)

            // ASE-GCM needs GCMParameterSpec

            // ASE-GCM needs GCMParameterSpec
            cipher.init(Cipher.ENCRYPT_MODE, aesKeyFromPassword, GCMParameterSpec(TAG_LENGTH_BIT, iv))

            val cipherText = cipher.doFinal(pText)

            // prefix IV and Salt to cipher text

            // prefix IV and Salt to cipher text

            return ByteBuffer.allocate(iv.size + salt.size + cipherText.size)
                .put(iv)
                .put(salt)
                .put(cipherText)
                .array()
        }

        fun decryptFile(fromEncryptedFile: String, password: String): ByteArray {

            // read a file
            val fileContent = Files.readAllBytes(Paths.get(fromEncryptedFile))
            return decrypt(fileContent, password)
        }

        private fun decrypt(cText: ByteArray, password: String): ByteArray {
            // get back the iv and salt that was prefixed in the cipher text
            // get back the iv and salt that was prefixed in the cipher text
            val bb: ByteBuffer = ByteBuffer.wrap(cText)

            val iv = ByteArray(12)
            bb.get(iv)

            val salt = ByteArray(16)
            bb.get(salt)

            val cipherText = ByteArray(bb.remaining())
            bb.get(cipherText)

            // get back the aes key from the same password and salt

            // get back the aes key from the same password and salt
            val aesKeyFromPassword = CryptoUtils.getAESKeyFromPassword(password.toCharArray(), salt)

            val cipher = Cipher.getInstance(ENCRYPT_ALGO)

            cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, GCMParameterSpec(TAG_LENGTH_BIT, iv))

            return cipher.doFinal(cipherText)
        }
    }

}