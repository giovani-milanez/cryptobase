LOCAL_PATH:= $(call my-dir)

local_src_files := \
	ACStatusInfo.cpp \
	AsymmetricKey.cpp \
	Attribute.cpp \
	AttributeCertificate.cpp \
	AttributeCertificateInfo.cpp \
	AttributeCertificateReq.cpp \
	AttributeCertificateReqInfo.cpp \
	AttributeCertificateResp.cpp \
	AttributeCertificateSearchInfo.cpp \
	AttributeCertificateValidity.cpp \
	ByteArray.cpp \
	Certificate.cpp \
	CertificateRevocationList.cpp \
	Exception.cpp \
	Extension.cpp \
	GeneralizedTime.cpp \
	Holder.cpp \
	IssuerSerial.cpp \
	MessageDigest.cpp \
	ObjectDigestInfo.cpp \
	ObjectIdentifier.cpp \
	PrivateKey.cpp \
	PublicKey.cpp \
	RevokedCertificate.cpp \
	TimeFunctions.cpp \
	x509ac.c \
	x509acreq.c \
	x509acresp.c \
	x509ac-supp.c \
	x509attr.c \
	x509attr-supp.c \
	X509Name.cpp \
	../jni/ac.cpp

local_c_includes := \
	$(NDK_PROJECT_PATH) \
	$(NDK_PROJECT_PATH)/include


include $(CLEAR_VARS)
LOCAL_MODULE := crypto-prebuilt
LOCAL_SRC_FILES := ../jni/libcrypto.so
LOCAL_EXPORT_C_INCLUDES := ../jni
include $(PREBUILT_SHARED_LIBRARY)


#######################################

# target
include $(CLEAR_VARS)
LOCAL_SRC_FILES += $(local_src_files)
LOCAL_C_INCLUDES += jni $(local_c_includes)
LOCAL_LDLIBS += -lz
LOCAL_CFLAGS += -std=gnu++11 -fexceptions -frtti -DANDROID_BUILD
LOCAL_SRC_FILES += $(arm_src_files)

ifeq ($(TARGET_SIMULATOR),true)
	# Make valgrind happy.
	LOCAL_CFLAGS += -DPURIFY
    LOCAL_LDLIBS += -ldl
endif
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE:= libcryptobase
LOCAL_SHARED_LIBRARIES += crypto-prebuilt
LOCAL_SHARED_LIBRARIES += libstlport_static
LOCAL_LDLIBS := -llog 
LOCAL_C_INCLUDES += external/stlport/stlport bionic/ bionic/libstdc++/include
include $(BUILD_SHARED_LIBRARY)
