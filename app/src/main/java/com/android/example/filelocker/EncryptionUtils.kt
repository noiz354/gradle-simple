package com.android.example.filelocker

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.util.Base64
import androidx.annotation.Nullable
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.security.spec.KeySpec
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.coroutines.CoroutineContext
import kotlin.random.Random
import kotlin.system.measureTimeMillis
import kotlin.time.ExperimentalTime
import kotlin.time.measureTimedValue

class EncryptionUtils {
    companion object : CoroutineScope{

        private const val ALLOWED_CHARACTERS = "0123456789qwertyuiopasdfghjklzxcvbnm"

        fun getRandomString(sizeOfPasswordString: Int): String {
            val random = Random(sizeOfPasswordString)
            val sb = java.lang.StringBuilder(sizeOfPasswordString)
            for (i in 0 until sizeOfPasswordString) {
                sb.append(ALLOWED_CHARACTERS[random.nextInt(ALLOWED_CHARACTERS.length)])
            }
            return sb.toString()

        }

        fun persistPassword(context: Context, filename: String, x : (SharedPreferences.Editor) -> Unit){
            val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

            val sharedPreferences = EncryptedSharedPreferences.create(
                filename,
                masterKeyAlias,
                context,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )

            val editor = sharedPreferences.edit()

            x.invoke(editor)

            editor.apply()
        }

        fun retrievePassword(context: Context, filename: String, x : (SharedPreferences) -> String) : String{
            val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

            val sharedPreferences = EncryptedSharedPreferences.create(
                filename,
                masterKeyAlias,
                context,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )

            return x.invoke(sharedPreferences)
        }

        /**
         * let it empty in order to detect using ifEmpty
         */
        const val KEY_PASSWORD_DEFAULT_VALUE = ""
        const val KEY_PASSWORD_VALUE_PREF = "KEY_PASSWORD_VALUE_PREF"
        const val KEY_PASSWORD_FILENAME = "iris_key.bin"

        const val ALGO_TRANSFORMATION_STRING = "AES/GCM/NoPadding"
        const val IV_SIZE = 96
        const val TAG_BIT_LENGTH = 128
        const val TAG = "sample"

        const val GCM_IV_LENGTH = 12
        const val GCM_TAG_LENGTH = 16

        private fun generateSecretKey(passcode: CharArray, salt: ByteArray): SecretKey {
            // Initialize PBE with password
            val factory: SecretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val spec: KeySpec = PBEKeySpec(passcode, salt, 65536, 256)
            val tmp: SecretKey = factory.generateSecret(spec)
            return SecretKeySpec(tmp.encoded, "AES")
        }

        @Nullable
        @JvmStatic
        suspend fun getSecretKey(context: Context, fileName: String = "default_secret_key", saltPrefName: String = "salt", userPasscode: CharArray,
                         getSalt: (context: Context, fileName: String, saltPrefName: String) -> String,
                         persistSalt : (context: Context, fileName: String, saltPrefName: String, saltValue:String) -> Unit = {_,_,_,_ -> }
        ) : SecretKey {
            val existingSalt = getSalt.invoke(context, fileName, saltPrefName)
            return if( existingSalt.isBlank() ){
                // Generate a random 8 byte salt
                val salt = ByteArray(8).apply {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        SecureRandom.getInstanceStrong().nextBytes(this)
                    } else {
                        SecureRandom().nextBytes(this)
                    }
                }
                val secretKey = generateSecretKey(userPasscode, salt)
                persistSalt.invoke(context, fileName, saltPrefName, Base64.encodeToString(salt, Base64.DEFAULT))
                secretKey
            }else{
                val salt = Base64.decode(existingSalt, Base64.DEFAULT)
                generateSecretKey(userPasscode, salt)
            }
        }

        fun getSecretKeyFlow(context: Context, fileName: String = "default_secret_key", saltPrefName: String = "salt", userPasscode: CharArray,
                         getSalt: (context: Context, fileName: String, saltPrefName: String) -> String,
                         persistSalt : (context: Context, fileName: String, saltPrefName: String, saltValue:String) -> Unit = {_,_,_,_ -> }
        ) : Flow<SecretKey>{
            return flow {
                val secretKey = getSecretKey(
                    context,
                    fileName,
                    saltPrefName,
                    userPasscode,
                    getSalt,
                    persistSalt
                )
                emit(secretKey)
            }
        }

        @JvmStatic
        fun cancelJobs(){
            coroutineContext.cancel()
        }

        @OptIn(ExperimentalTime::class)
        fun encrypt(text:String, secret:SecretKey): String{
            val (byteBuffer, elapsed) = measureTimedValue {
                val secureRandom = SecureRandom.getInstance("SHA1PRNG")

                // original iv size
//            val iv = ByteArray(IV_SIZE)

                // using this size
                val iv = ByteArray(GCM_IV_LENGTH)


                secureRandom.nextBytes(iv)

                // original iv size
//            val gcmParamSpec = GCMParameterSpec(TAG_BIT_LENGTH, iv)

                val gcmParamSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)

                // Now encrypt the database key with PBE
                val cipher = Cipher.getInstance(ALGO_TRANSFORMATION_STRING)
                cipher.init(Cipher.ENCRYPT_MODE, secret, gcmParamSpec, secureRandom)
                cipher.updateAAD(TAG.toByteArray(StandardCharsets.UTF_8))
                val ciphertext: ByteArray = cipher.doFinal(text.toByteArray(StandardCharsets.UTF_8))

                val byteBuffer = ByteBuffer.allocate(iv.size + ciphertext.size)
                byteBuffer.put(iv)
                byteBuffer.put(ciphertext)
                byteBuffer
            }


//            return byteBuffer.array()
            return Base64.encodeToString(byteBuffer.array(), Base64.DEFAULT)
        }

        @OptIn(ExperimentalTime::class)
        fun decrypt(encryptedText:String, secret:SecretKey): String {
            val aesWrappedKey = Base64.decode(encryptedText, Base64.DEFAULT)

            val (result, elapsed) = measureTimedValue {
                val secureRandom = SecureRandom.getInstance("SHA1PRNG")

                val byteBuffer: ByteBuffer = ByteBuffer.wrap(aesWrappedKey)
//            val iv = ByteArray(IV_SIZE)
                val iv = ByteArray(GCM_IV_LENGTH)
                byteBuffer.get(iv)
//            val gcmParamSpec = GCMParameterSpec(TAG_BIT_LENGTH, iv)
                val gcmParamSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
                val cipher = Cipher.getInstance(ALGO_TRANSFORMATION_STRING)
                cipher.init(Cipher.DECRYPT_MODE, secret, gcmParamSpec, secureRandom)
                cipher.updateAAD(TAG.toByteArray(StandardCharsets.UTF_8))

                val encryptedPayload = ByteArray(byteBuffer.remaining())
                byteBuffer.get(encryptedPayload)

                cipher.doFinal(encryptedPayload)
            }

            return String(result)


        }

        fun decrypt(encryptedText:String, passcode: CharArray, salt:String): String {
            val aesWrappedKey = Base64.decode(encryptedText, Base64.DEFAULT)

            val _salt = Base64.decode(salt, Base64.DEFAULT)
            val secret: SecretKey = generateSecretKey(passcode, _salt)

            val secureRandom = SecureRandom.getInstance("SHA1PRNG")

            val byteBuffer: ByteBuffer = ByteBuffer.wrap(aesWrappedKey)
//            val iv = ByteArray(IV_SIZE)
            val iv = ByteArray(GCM_IV_LENGTH)
            byteBuffer.get(iv)
//            val gcmParamSpec = GCMParameterSpec(TAG_BIT_LENGTH, iv)
            val gcmParamSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
            val cipher = Cipher.getInstance(ALGO_TRANSFORMATION_STRING)
            cipher.init(Cipher.DECRYPT_MODE, secret, gcmParamSpec, secureRandom)
            cipher.updateAAD(TAG.toByteArray(StandardCharsets.UTF_8))

            val encryptedPayload = ByteArray(byteBuffer.remaining())
            byteBuffer.get(encryptedPayload)

            return String(cipher.doFinal(encryptedPayload))
        }

        override val coroutineContext: CoroutineContext
            get() = SupervisorJob() + Dispatchers.IO
    }
}