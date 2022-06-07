package com.example.testapp

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import androidx.test.runner.AndroidJUnit4
import com.android.example.filelocker.Constants
import com.android.example.filelocker.EncryptionUtils
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom
import javax.crypto.SecretKey
import kotlin.time.ExperimentalTime
import kotlin.time.measureTimedValue

@RunWith(AndroidJUnit4::class)
class EncryptionsUtilsTest {

    @Test
    fun testBrowser(){
        val _context = androidx.test.InstrumentationRegistry.getTargetContext()
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("http://www.google.com"))
        val queryIntentActivities = _context.packageManager.queryIntentActivities(intent, PackageManager.MATCH_ALL)
        System.out.println(queryIntentActivities)
        intent.setPackage(queryIntentActivities[0].activityInfo.packageName)
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        _context.startActivity(intent)
    }
    @OptIn(ExperimentalTime::class)
    @Test
    fun testGetSecretKey(){
        val _context = androidx.test.InstrumentationRegistry.getTargetContext()
        var persistSaltToggle = false
        var getSaltToggle = false
        var salt = ""
        val getSalt : (Context, String, String) -> String =  { context, fileName, saltPrefName ->
            val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

            val sharedPreferences = EncryptedSharedPreferences.create(
                fileName,
                masterKeyAlias,
                context,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )

            getSaltToggle = true
            sharedPreferences.getString(saltPrefName, "")?:""

            // uncomment below for speed up retrieve
//            salt
        }
        val persistSalt : (Context, String, String, String) -> Unit = {
                context, fileName, saltPrefName, saltValue ->
            val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

            val sharedPreferences = EncryptedSharedPreferences.create(
                fileName,
                masterKeyAlias,
                context,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
            val editor = sharedPreferences.edit()

            editor.putString(saltPrefName, saltValue)

            persistSaltToggle = true

            editor.apply()

//            saltValue

            // uncomment below for faster saving
//            salt = saltValue
//            salt
        }

//        class A {
//            fun printX(x: Any){
//                println(x)
//            }
//        }
//
//        fun test(block: A.() -> Unit){
//
//        }
//
//        test{
//            printX("Wkwkwkwwk")
//        }
//
//        class B<out T>{
//            fun check(t:T){
//
//            }
//
//            fun returnT() : T{
//                return T
//            }
//        }

        var printLog = java.lang.StringBuilder("")

        val (password, elapsedPassword) = measureTimedValue {
            EncryptionUtils.retrievePassword(_context, EncryptionUtils.KEY_PASSWORD_FILENAME){
                it.getString(EncryptionUtils.KEY_PASSWORD_VALUE_PREF, EncryptionUtils.KEY_PASSWORD_DEFAULT_VALUE)?:EncryptionUtils.KEY_PASSWORD_DEFAULT_VALUE
            }.ifEmpty {
                val randomString = EncryptionUtils.getRandomString(128)
                EncryptionUtils.persistPassword(_context, EncryptionUtils.KEY_PASSWORD_FILENAME){
                    it.putString(EncryptionUtils.KEY_PASSWORD_VALUE_PREF, randomString)
                }
                randomString
            }
        }

        printLog = printLog.append("elapsedPassword "+elapsedPassword+"\n")
        
        

        var test: SecretKey? = null
        runBlocking {
            EncryptionUtils.getSecretKeyFlow(
                _context, userPasscode = password.toCharArray(),
                getSalt = getSalt, persistSalt = persistSalt
            )
            .collect{
                test = it
            }
        }




        /**
         * persist one here
         */
        val (secretKey, __elapsed) = measureTimedValue {
            runBlocking {
                EncryptionUtils.getSecretKey(
                    _context, userPasscode = password.toCharArray(),
                    getSalt = getSalt, persistSalt = persistSalt
                )
            }
        }
        println(__elapsed)

        printLog = printLog.append("first time secret key "+__elapsed+"\n")

//        assert(getSaltToggle)
//        assert(persistSaltToggle)

        val (secondAttemptSecretKey, _elapsed) = measureTimedValue {
            runBlocking {
                EncryptionUtils.getSecretKey(
                    _context, userPasscode = password.toCharArray(),
                    getSalt = getSalt
                )
            }
        }
        println(_elapsed)

        printLog = printLog.append("second time secret key "+_elapsed+"\n")

//        assert(persistSaltToggle)
//        assert(getSaltToggle)

        assert(secretKey.equals(secondAttemptSecretKey))

//        var rawByteKey: ByteArray= generateRandomKey()
//        var dbCharKey = rawByteKey.toHex()

//        val text = "saya makan nasi aja deh biar makan nasinya enak"
//        val encrypt = EncryptionUtils.encrypt(dbCharKey.contentToString(), secretKey)
//        val encrypt = EncryptionUtils.encrypt(text, secretKey)
//        val encrypt = EncryptionUtils.encrypt(rawByteKey, secretKey)
//        Log.d("TEST", encrypt)
//        println(encrypt)
//        val decrypt = EncryptionUtils.decrypt(encrypt, secondAttemptSecretKey)

//        val salt = getSalt.invoke(_context, "default_secret_key", "salt")
//        val decrypt = EncryptionUtils.decrypt(encrypt, salt, password.toCharArray())
//        val decrypt = EncryptionUtils.decrypt(encrypt, secretKey)
//        assert(rawByteKey.contentToString().equals(decrypt))

//        val text = "saya makin nasi"
//        val encrypt = EncryptionUtils.encrypt(text, secretKey)
//        val decrypt = EncryptionUtils.decrypt(encrypt, secretKey)
//        assert(text.equals(decrypt))

        // uncoment this without salt variable
//        val text = "saya makin nasi"
//        val encrypt = EncryptionUtils.encrypt(text, secretKey)
//        val decrypt = EncryptionUtils.decrypt(encrypt,password.toCharArray(), salt)
//        assert(text.equals(decrypt))


        // this is for without encrypted shared pref
//        val (_, elapsed) = measureTimedValue {
////            val text = "saya makin nasi"
//            val encrypt = EncryptionUtils.encrypt(Constants.twoTimesLongText, secretKey)
//            val decrypt = EncryptionUtils.decrypt(encrypt,password.toCharArray(), salt)
//            text.equals(decrypt)
//        }


        val (encrypt, encryptionElapsed) = measureTimedValue {
            EncryptionUtils.encrypt(Constants.twoTimesLongText, secretKey)
        }

        printLog = printLog.append("encryptionElapsed "+encryptionElapsed+"\n")

        val (decrypt, decryptionElapsed) = measureTimedValue {
           EncryptionUtils.decrypt(encrypt,secondAttemptSecretKey)
        }

        printLog = printLog.append("decryptionElapsed "+decryptionElapsed+"\n")

        assert(Constants.twoTimesLongText.equals(decrypt))

        printLog = printLog.append("DONE\n")
        System.out.println(printLog)
    }


    private val HEX_CHARS = "0123456789ABCDEF".toCharArray()

    /**
     * Extension function that converts a ByteArray to a hex encoded String
     */
    fun ByteArray.toHex(): CharArray {
        val result = StringBuilder()
        forEach {
            val octet = it.toInt()
            val firstIndex = (octet and 0xF0).ushr(4)
            val secondIndex = octet and 0x0F
            result.append(HEX_CHARS[firstIndex])
            result.append(HEX_CHARS[secondIndex])
        }
        return result.toString().toCharArray()
    }

    fun generateRandomKey(): ByteArray =
        ByteArray(32).apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                SecureRandom.getInstanceStrong().nextBytes(this)
            } else {
                SecureRandom().nextBytes(this)
            }
        }


}