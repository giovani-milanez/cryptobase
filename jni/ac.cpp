/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "cryptobase/AttributeCertificate.hpp"
#include "cryptobase/Certificate.hpp"
#include "cryptobase/X509Name.hpp"

#include <openssl/objects.h>
#include <openssl/evp.h>


#include <string>
#include <iostream>
#include <jni.h>
#include <android/log.h>


#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "MyApp", __VA_ARGS__))

extern "C"
{

/* This is a trivial JNI example where we use a native method
 * to return a new VM String. See the corresponding Java source
 * file located at:
 *
 *   apps/samples/hello-jni/project/src/com/example/hellojni/HelloJni.java
 */

jint JNI_OnLoad( JavaVM *vm, void *pvt )
	{
	OpenSSL_add_all_algorithms();
	return JNI_VERSION_1_6;
	}

void JNI_OnUnload( JavaVM *vm, void *pvt )
	{
	}

jlong
Java_cryptobase_AttributeCertificate_create( JNIEnv* env,
                                                  jobject thiz, jstring pem )
{
	cryptobase::AttributeCertificate *cert = new cryptobase::AttributeCertificate(env->GetStringUTFChars(pem, 0));
	long ptr = (long)cert;
	return (jlong)ptr;
}

jboolean
Java_cryptobase_AttributeCertificate_verifyValidity( JNIEnv* env,
                                                  jobject thiz, jlong ptr)
{
	cryptobase::AttributeCertificate *cert = (cryptobase::AttributeCertificate *)ptr;
	return (jboolean)cert->verifyValidity();
}

jboolean
Java_cryptobase_AttributeCertificate_verifySignature( JNIEnv* env,
                                                  jobject thiz, jlong ptr, jstring certLocation )
{
	cryptobase::AttributeCertificate *cert = (cryptobase::AttributeCertificate *)ptr;
	try{
		cryptobase::Certificate signCert = cryptobase::Certificate::fromFile(env->GetStringUTFChars(certLocation, 0));
		return (jboolean)cert->verifySignature(signCert);
	}catch(...){
		return (jboolean)false;
	}
}

void
Java_cryptobase_AttributeCertificate_destroy( JNIEnv* env,
                                                  jobject thiz, jlong ptr )
{
	delete (cryptobase::AttributeCertificate *)ptr;
}

jlong
Java_cryptobase_AttributeCertificate_getNotAfter( JNIEnv* env,
                                                  jobject thiz, jlong ptr )
{	
	cryptobase::AttributeCertificate *cert = (cryptobase::AttributeCertificate *)ptr;	
	time_t epoch = cert->getInfo().getValidity().getNotAfter().getEpoch();
	return (jlong)epoch;

}

jlong
Java_cryptobase_AttributeCertificate_getNotBefore( JNIEnv* env,
                                                  jobject thiz, jlong ptr )
{
	cryptobase::AttributeCertificate *cert = (cryptobase::AttributeCertificate *)ptr;
	time_t epoch = cert->getInfo().getValidity().getNotBefore().getEpoch();
	return (jlong)epoch;
}


jstring
Java_cryptobase_AttributeCertificate_getHolder( JNIEnv* env,
                                                  jobject thiz, jlong ptr )
{
	cryptobase::AttributeCertificate *cert = (cryptobase::AttributeCertificate *)ptr;
	std::string cn = cert->getInfo().getHolder().getHolderEntityName().getEntries(cryptobase::X509Name::EntryType::COMMON_NAME)[0];
	jstring result = env->NewStringUTF(cn.c_str());
	return result;
}

jstring
Java_cryptobase_AttributeCertificate_getAttribute( JNIEnv* env,
                                                  jobject thiz, jlong ptr, jstring attrOid )
{
	cryptobase::AttributeCertificate *cert = (cryptobase::AttributeCertificate *)ptr;
	std::string attrOidStr = env->GetStringUTFChars(attrOid, 0);
	std::string out;
	for(auto attr : cert->getInfo().getAttributes())
	{
		if(attr.getOid().getOidStr() == attrOidStr)
		{
			for(auto v : attr.getValues())
				out += std::string((const char *)v.begin(), v.size())+"\n";
		}
	}
	jstring result = env->NewStringUTF(out.c_str());
	return result;
}

}
