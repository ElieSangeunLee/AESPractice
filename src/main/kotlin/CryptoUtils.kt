import java.security.SecureRandom
import java.security.spec.KeySpec
import java.util.ArrayList
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.min

class CryptoUtils {
    companion object {
        fun getRandomNonce(numBytes: Int): ByteArray {
            val nonce = ByteArray(numBytes)
            SecureRandom().nextBytes(nonce)
            return nonce
        }

        fun getAESKey(keySize: Int): SecretKey {
            val keyGen = KeyGenerator.getInstance("AES")
            keyGen.init(keySize, SecureRandom.getInstanceStrong())
            return keyGen.generateKey()
        }

        fun getAESKeyFromPassword(password: CharArray, salt: ByteArray): SecretKey {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val iterationCount = 65536
            val keyLength = 256
            val spec: KeySpec = PBEKeySpec(password, salt, iterationCount, keyLength)
            return SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
        }

        fun hex(bytes: ByteArray): String {
            val result = StringBuilder()
            for (b in bytes) {
                result.append(String.format("%02x", b))
            }
            return result.toString()
        }

        fun hexWithBlockSize(bytes: ByteArray, blockSize: Int): String {
            val hex = hex(bytes)

            // one hex = 2 chars
            val blockSizeCalculated = blockSize * 2

            // better idea how to print this?
            val result: MutableList<String> = ArrayList()
            var index = 0
            while (index < hex.length) {
                result.add(hex.substring(index, min(index + blockSizeCalculated, hex.length)))
                index += blockSizeCalculated
            }

            return result.toString()
        }
    }
}