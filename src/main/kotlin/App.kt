import EncryptorAesGcm.Companion.UTF_8

// EncryptorAesGcm
//fun main(args: Array<String>) {
//    val OUTPUT_FORMAT = "%-30s:%s"
//
//    val pText = "Hello World AES-GCM, Welcome to Cryptography!"
//
//    // encrypt and decrypt need the same key.
//    // get AES 256 bits (32 bytes) key
//    val secretKey = CryptoUtils.getAESKey(AES_KEY_BIT)
//
//    // encrypt and decrypt need the same IV.
//    // AES-GCM needs IV 96-bit (12 bytes)
//    val iv = CryptoUtils.getRandomNonce(IV_LENGTH_BYTE)
//
//    val encryptedText = EncryptorAesGcm.encryptWithPrefixIV(pText.toByteArray(UTF_8), secretKey, iv)
//
//    println("\n------ AES GCM Encryption ------")
//    println(String.format(OUTPUT_FORMAT, "Input (plain text)", pText))
//    println(String.format(OUTPUT_FORMAT, "Key (hex)", CryptoUtils.hex(secretKey.encoded)))
//    println(String.format(OUTPUT_FORMAT, "IV  (hex)", CryptoUtils.hex(iv)))
//    println(String.format(OUTPUT_FORMAT, "Encrypted (hex) ", CryptoUtils.hex(encryptedText)))
//    println(
//        String.format(
//            OUTPUT_FORMAT,
//            "Encrypted (hex) (block = 16)",
//            CryptoUtils.hexWithBlockSize(encryptedText, 16)
//        )
//    )
//
//    println("\n------ AES GCM Decryption ------")
//    println(String.format(OUTPUT_FORMAT, "Input (hex)", CryptoUtils.hex(encryptedText)))
//    println(
//        String.format(
//            OUTPUT_FORMAT,
//            "Input (hex) (block = 16)",
//            CryptoUtils.hexWithBlockSize(encryptedText, 16)
//        )
//    )
//    println(String.format(OUTPUT_FORMAT, "Key (hex)", CryptoUtils.hex(secretKey.encoded)))
//
//    val decryptedText = EncryptorAesGcm.decryptWithPrefixIV(encryptedText, secretKey)
//
//    println(String.format(OUTPUT_FORMAT, "Decrypted (plain text)", decryptedText))
//
//}


//fun main() {
//    val OUTPUT_FORMAT = "%-30s:%s"
//    val PASSWORD = "this is a password"
//    val pText = "AES-GSM Password-Bases encryption!"
//
//    val encryptedTextBase64 = EncryptorAesGcmPassword.encrypt(pText.toByteArray(UTF_8), PASSWORD)
//
//    println("\n------ AES GCM Password-based Encryption ------")
//    println(String.format(OUTPUT_FORMAT, "Input (plain text)", pText))
//    println(String.format(OUTPUT_FORMAT, "Encrypted (base64) ", encryptedTextBase64))
//
//    println("\n------ AES GCM Password-based Decryption ------")
//    println(String.format(OUTPUT_FORMAT, "Input (base64)", encryptedTextBase64))
//
//    val decryptedText = EncryptorAesGcmPassword.decrypt(encryptedTextBase64, PASSWORD)
//    println(String.format(OUTPUT_FORMAT, "Decrypted (plain text)", decryptedText))
//
//}

fun main(){
    val password = "password123"
    val fromFile = "readme.txt" // from resources folder

    val toFile = "/Users/elie/IdeaProjects/untitled1/readme.encrypted.txt"

    // encrypt file
    EncryptorAesGcmPasswordFile.encryptFile(fromFile, toFile, password)


    // decrypt file
    val decryptedText = EncryptorAesGcmPasswordFile.decryptFile(toFile, password)
    val pText = String(decryptedText, UTF_8)
    println(pText)
}