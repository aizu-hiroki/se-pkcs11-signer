#ifndef SE_PKCS11_SIGNER_PKCS11_TYPES_H
#define SE_PKCS11_SIGNER_PKCS11_TYPES_H

/*
 * Minimal PKCS#11 v2.40 type/struct/constant subset, defined independently
 * from the OASIS reference headers so Swift's Clang importer produces
 * struct layouts that match the standard LP64 (natural alignment, no
 * #pragma pack) ABI used on macOS. Only the surface actually implemented
 * by this module is declared here.
 */

typedef unsigned char CK_BYTE;
typedef CK_BYTE CK_UTF8CHAR;
typedef CK_BYTE CK_CHAR;
typedef CK_BYTE CK_BBOOL;
typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_FLAGS;

typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_USER_TYPE;
typedef CK_ULONG CK_STATE;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_MECHANISM_TYPE;

#define CK_TRUE 1
#define CK_FALSE 0
#define CK_INVALID_HANDLE 0UL

typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef struct CK_TOKEN_INFO {
    CK_UTF8CHAR label[32];
    CK_UTF8CHAR manufacturerID[32];
    CK_UTF8CHAR model[16];
    CK_CHAR serialNumber[16];
    CK_FLAGS flags;
    CK_ULONG ulMaxSessionCount;
    CK_ULONG ulSessionCount;
    CK_ULONG ulMaxRwSessionCount;
    CK_ULONG ulRwSessionCount;
    CK_ULONG ulMaxPinLen;
    CK_ULONG ulMinPinLen;
    CK_ULONG ulTotalPublicMemory;
    CK_ULONG ulFreePublicMemory;
    CK_ULONG ulTotalPrivateMemory;
    CK_ULONG ulFreePrivateMemory;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
    CK_UTF8CHAR utcTime[16];
} CK_TOKEN_INFO;

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    void *pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    void *pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;

/* Object classes (CKO_*) */
#define CKO_CERTIFICATE 0x00000001UL
#define CKO_PUBLIC_KEY  0x00000002UL
#define CKO_PRIVATE_KEY 0x00000003UL

/* Key types (CKK_*) */
#define CKK_EC 0x00000003UL

/* Attribute types (CKA_*) */
#define CKA_CLASS     0x00000000UL
#define CKA_LABEL     0x00000003UL
#define CKA_VALUE     0x00000011UL
#define CKA_ID        0x00000102UL
#define CKA_KEY_TYPE  0x00000100UL
#define CKA_EC_PARAMS 0x00000180UL
#define CKA_EC_POINT  0x00000181UL

/* Mechanism types (CKM_*) */
#define CKM_ECDSA 0x00001041UL

/* User types (CKU_*) */
#define CKU_USER 1UL

/* Session flags (CKF_*) */
#define CKF_RW_SESSION     0x00000002UL
#define CKF_SERIAL_SESSION 0x00000004UL

/* Token flags (CKF_*) */
#define CKF_LOGIN_REQUIRED       0x00000004UL
#define CKF_USER_PIN_INITIALIZED 0x00000008UL
#define CKF_TOKEN_INITIALIZED    0x00000400UL

/* Return values (CKR_*) */
#define CKR_OK                           0x00000000UL
#define CKR_GENERAL_ERROR                0x00000005UL
#define CKR_FUNCTION_FAILED              0x00000006UL
#define CKR_ARGUMENTS_BAD                0x00000007UL
#define CKR_ATTRIBUTE_TYPE_INVALID       0x00000012UL
#define CKR_DEVICE_ERROR                 0x00000030UL
#define CKR_KEY_HANDLE_INVALID           0x00000060UL
#define CKR_MECHANISM_INVALID            0x00000070UL
#define CKR_OBJECT_HANDLE_INVALID        0x00000082UL
#define CKR_OPERATION_NOT_INITIALIZED    0x00000091UL
#define CKR_USER_ALREADY_LOGGED_IN       0x00000100UL
#define CKR_SESSION_HANDLE_INVALID       0x000000B3UL
#define CKR_TOKEN_NOT_PRESENT            0x000000E0UL
#define CKR_BUFFER_TOO_SMALL             0x00000150UL
#define CKR_CRYPTOKI_NOT_INITIALIZED     0x00000190UL
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x00000191UL

#endif
