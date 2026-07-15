import CCryptoki
import Foundation
import SEBlob

enum Config {
    static let tokenLabel = ProcessInfo.processInfo.environment["SE_PKCS11_SIGNER_TOKEN_LABEL"] ?? "Secure Enclave"
    static let manufacturerID = ProcessInfo.processInfo.environment["SE_PKCS11_SIGNER_MANUFACTURER"] ?? "Apple"
    static var keyDir: String { SEBlob.defaultKeyDir }
}

private func fillPadded(_ buffer: UnsafeMutableRawBufferPointer, with string: String, pad: UInt8 = 0x20) {
    let bytes = Array(string.utf8)
    for i in 0..<buffer.count {
        buffer[i] = i < bytes.count ? bytes[i] : pad
    }
}

// MARK: - General purpose

@_cdecl("C_Initialize")
public func sePkcs11Signer_C_Initialize(_ pInitArgs: UnsafeMutableRawPointer?) -> CK_RV {
    Pkcs11State.shared.initialize()
}

@_cdecl("C_Finalize")
public func sePkcs11Signer_C_Finalize(_ pReserved: UnsafeMutableRawPointer?) -> CK_RV {
    Pkcs11State.shared.finalize()
}

// MARK: - Slot and token management

@_cdecl("C_GetSlotList")
public func sePkcs11Signer_C_GetSlotList(
    _ tokenPresent: CK_BBOOL,
    _ pSlotList: UnsafeMutablePointer<CK_ULONG>?,
    _ pulCount: UnsafeMutablePointer<CK_ULONG>?
) -> CK_RV {
    guard Pkcs11State.shared.isInitialized else { return CK_RV(CKR_CRYPTOKI_NOT_INITIALIZED) }
    guard let pulCount else { return CK_RV(CKR_ARGUMENTS_BAD) }

    if pSlotList == nil {
        pulCount.pointee = 1
        return CK_RV(CKR_OK)
    }
    guard pulCount.pointee >= 1 else {
        pulCount.pointee = 1
        return CK_RV(CKR_BUFFER_TOO_SMALL)
    }
    pSlotList!.pointee = 0
    pulCount.pointee = 1
    return CK_RV(CKR_OK)
}

@_cdecl("C_GetTokenInfo")
public func sePkcs11Signer_C_GetTokenInfo(
    _ slotID: CK_ULONG,
    _ pInfo: UnsafeMutablePointer<CK_TOKEN_INFO>?
) -> CK_RV {
    guard Pkcs11State.shared.isInitialized else { return CK_RV(CKR_CRYPTOKI_NOT_INITIALIZED) }
    guard slotID == 0 else { return CK_RV(CKR_TOKEN_NOT_PRESENT) }
    guard let pInfo else { return CK_RV(CKR_ARGUMENTS_BAD) }

    var info = CK_TOKEN_INFO()
    withUnsafeMutableBytes(of: &info.label) { fillPadded($0, with: Config.tokenLabel) }
    withUnsafeMutableBytes(of: &info.manufacturerID) { fillPadded($0, with: Config.manufacturerID) }
    withUnsafeMutableBytes(of: &info.model) { fillPadded($0, with: "Secure Enclave") }
    withUnsafeMutableBytes(of: &info.serialNumber) { fillPadded($0, with: "1") }
    withUnsafeMutableBytes(of: &info.utcTime) { fillPadded($0, with: "", pad: 0x20) }
    info.flags = CK_ULONG(CKF_TOKEN_INITIALIZED) | CK_ULONG(CKF_USER_PIN_INITIALIZED)

    pInfo.pointee = info
    return CK_RV(CKR_OK)
}

// MARK: - Session management

@_cdecl("C_OpenSession")
public func sePkcs11Signer_C_OpenSession(
    _ slotID: CK_ULONG,
    _ flags: CK_ULONG,
    _ pApplication: UnsafeMutableRawPointer?,
    _ notify: UnsafeMutableRawPointer?,
    _ phSession: UnsafeMutablePointer<CK_ULONG>?
) -> CK_RV {
    guard Pkcs11State.shared.isInitialized else { return CK_RV(CKR_CRYPTOKI_NOT_INITIALIZED) }
    guard slotID == 0 else { return CK_RV(CKR_TOKEN_NOT_PRESENT) }
    guard let phSession else { return CK_RV(CKR_ARGUMENTS_BAD) }

    phSession.pointee = Pkcs11State.shared.openSession()
    return CK_RV(CKR_OK)
}

@_cdecl("C_CloseSession")
public func sePkcs11Signer_C_CloseSession(_ hSession: CK_ULONG) -> CK_RV {
    Pkcs11State.shared.closeSession(hSession) ? CK_RV(CKR_OK) : CK_RV(CKR_SESSION_HANDLE_INVALID)
}

@_cdecl("C_Login")
public func sePkcs11Signer_C_Login(
    _ hSession: CK_ULONG,
    _ userType: CK_ULONG,
    _ pPin: UnsafeMutablePointer<CK_UTF8CHAR>?,
    _ ulPinLen: CK_ULONG
) -> CK_RV {
    guard Pkcs11State.shared.session(hSession) != nil else { return CK_RV(CKR_SESSION_HANDLE_INVALID) }
    // Secure Enclave keys are protected by the system's own access control
    // (Touch ID / device passcode) prompted at signing time, not by a PIN
    // known to this module, so the PIN itself is not verified here.
    return Pkcs11State.shared.login()
}

@_cdecl("C_Logout")
public func sePkcs11Signer_C_Logout(_ hSession: CK_ULONG) -> CK_RV {
    guard Pkcs11State.shared.session(hSession) != nil else { return CK_RV(CKR_SESSION_HANDLE_INVALID) }
    Pkcs11State.shared.logout()
    return CK_RV(CKR_OK)
}

// MARK: - Object management

private func attributeMatches(_ object: Pkcs11Object, type: CK_ULONG, value: Data) -> Bool {
    switch type {
    case CK_ULONG(CKA_CLASS):
        return value.count == MemoryLayout<CK_ULONG>.size
            && value.withUnsafeBytes { $0.load(as: CK_ULONG.self) } == object.classValue
    case CK_ULONG(CKA_ID):
        return value == object.id
    case CK_ULONG(CKA_LABEL):
        return value == Data(object.label.utf8)
    default:
        return true
    }
}

@_cdecl("C_FindObjectsInit")
public func sePkcs11Signer_C_FindObjectsInit(
    _ hSession: CK_ULONG,
    _ pTemplate: UnsafeMutablePointer<CK_ATTRIBUTE>?,
    _ ulCount: CK_ULONG
) -> CK_RV {
    guard let session = Pkcs11State.shared.session(hSession) else { return CK_RV(CKR_SESSION_HANDLE_INVALID) }
    guard !session.findActive else { return CK_RV(CKR_OPERATION_NOT_INITIALIZED) }

    var candidates = Pkcs11State.shared.objects()
    if let pTemplate {
        let template = UnsafeBufferPointer(start: pTemplate, count: Int(ulCount))
        for attr in template {
            guard let ptr = attr.pValue else { continue }
            let value = Data(bytes: ptr, count: Int(attr.ulValueLen))
            candidates = candidates.filter { attributeMatches($0, type: attr.type, value: value) }
        }
    }

    session.findQuery = candidates
    session.findCursor = 0
    session.findActive = true
    return CK_RV(CKR_OK)
}

@_cdecl("C_FindObjects")
public func sePkcs11Signer_C_FindObjects(
    _ hSession: CK_ULONG,
    _ phObject: UnsafeMutablePointer<CK_ULONG>?,
    _ ulMaxObjectCount: CK_ULONG,
    _ pulObjectCount: UnsafeMutablePointer<CK_ULONG>?
) -> CK_RV {
    guard let session = Pkcs11State.shared.session(hSession) else { return CK_RV(CKR_SESSION_HANDLE_INVALID) }
    guard session.findActive else { return CK_RV(CKR_OPERATION_NOT_INITIALIZED) }
    guard let phObject, let pulObjectCount else { return CK_RV(CKR_ARGUMENTS_BAD) }

    var count: CK_ULONG = 0
    let max = Int(ulMaxObjectCount)
    while count < max, session.findCursor < session.findQuery.count {
        phObject[Int(count)] = session.findQuery[session.findCursor].handle
        session.findCursor += 1
        count += 1
    }
    pulObjectCount.pointee = count
    return CK_RV(CKR_OK)
}

@_cdecl("C_FindObjectsFinal")
public func sePkcs11Signer_C_FindObjectsFinal(_ hSession: CK_ULONG) -> CK_RV {
    guard let session = Pkcs11State.shared.session(hSession) else { return CK_RV(CKR_SESSION_HANDLE_INVALID) }
    session.findActive = false
    session.findQuery = []
    session.findCursor = 0
    return CK_RV(CKR_OK)
}

private func attributeValue(_ object: Pkcs11Object, type: CK_ULONG) -> Data? {
    switch type {
    case CK_ULONG(CKA_CLASS):
        var v = object.classValue
        return Data(bytes: &v, count: MemoryLayout<CK_ULONG>.size)
    case CK_ULONG(CKA_ID):
        return object.id
    case CK_ULONG(CKA_LABEL):
        return Data(object.label.utf8)
    case CK_ULONG(CKA_KEY_TYPE):
        guard var v = object.keyType else { return nil }
        return Data(bytes: &v, count: MemoryLayout<CK_ULONG>.size)
    case CK_ULONG(CKA_EC_PARAMS):
        return object.ecParams
    case CK_ULONG(CKA_EC_POINT):
        return object.ecPoint
    default:
        return nil
    }
}

@_cdecl("C_GetAttributeValue")
public func sePkcs11Signer_C_GetAttributeValue(
    _ hSession: CK_ULONG,
    _ hObject: CK_ULONG,
    _ pTemplate: UnsafeMutablePointer<CK_ATTRIBUTE>?,
    _ ulCount: CK_ULONG
) -> CK_RV {
    guard Pkcs11State.shared.session(hSession) != nil else { return CK_RV(CKR_SESSION_HANDLE_INVALID) }
    guard let object = Pkcs11State.shared.object(handle: hObject) else { return CK_RV(CKR_OBJECT_HANDLE_INVALID) }
    guard let pTemplate else { return CK_RV(CKR_ARGUMENTS_BAD) }

    var rv = CK_RV(CKR_OK)
    let template = UnsafeMutableBufferPointer(start: pTemplate, count: Int(ulCount))
    for i in 0..<template.count {
        guard let value = attributeValue(object, type: template[i].type) else {
            template[i].ulValueLen = CK_ULONG(bitPattern: -1)
            rv = CK_RV(CKR_ATTRIBUTE_TYPE_INVALID)
            continue
        }
        if template[i].pValue == nil {
            template[i].ulValueLen = CK_ULONG(value.count)
        } else if Int(template[i].ulValueLen) < value.count {
            template[i].ulValueLen = CK_ULONG(bitPattern: -1)
            rv = CK_RV(CKR_BUFFER_TOO_SMALL)
        } else {
            value.withUnsafeBytes { template[i].pValue!.copyMemory(from: $0.baseAddress!, byteCount: value.count) }
            template[i].ulValueLen = CK_ULONG(value.count)
        }
    }
    return rv
}

// MARK: - Signing

@_cdecl("C_SignInit")
public func sePkcs11Signer_C_SignInit(
    _ hSession: CK_ULONG,
    _ pMechanism: UnsafeMutablePointer<CK_MECHANISM>?,
    _ hKey: CK_ULONG
) -> CK_RV {
    guard let session = Pkcs11State.shared.session(hSession) else { return CK_RV(CKR_SESSION_HANDLE_INVALID) }
    guard let mechanism = pMechanism?.pointee else { return CK_RV(CKR_ARGUMENTS_BAD) }
    guard mechanism.mechanism == CK_ULONG(CKM_ECDSA) else { return CK_RV(CKR_MECHANISM_INVALID) }
    guard let object = Pkcs11State.shared.object(handle: hKey), object.blob != nil,
          object.classValue == CK_ULONG(CKO_PRIVATE_KEY)
    else { return CK_RV(CKR_KEY_HANDLE_INVALID) }

    session.signObjectHandle = hKey
    session.signMechanism = mechanism.mechanism
    return CK_RV(CKR_OK)
}

private let ecdsaP256SignatureLength = 64 // raw r||s, 32 bytes each

@_cdecl("C_Sign")
public func sePkcs11Signer_C_Sign(
    _ hSession: CK_ULONG,
    _ pData: UnsafeMutablePointer<CK_BYTE>?,
    _ ulDataLen: CK_ULONG,
    _ pSignature: UnsafeMutablePointer<CK_BYTE>?,
    _ pulSignatureLen: UnsafeMutablePointer<CK_ULONG>?
) -> CK_RV {
    guard let session = Pkcs11State.shared.session(hSession) else { return CK_RV(CKR_SESSION_HANDLE_INVALID) }
    guard let pulSignatureLen else { return CK_RV(CKR_ARGUMENTS_BAD) }
    guard let hKey = session.signObjectHandle, session.signMechanism == CK_ULONG(CKM_ECDSA) else {
        return CK_RV(CKR_OPERATION_NOT_INITIALIZED)
    }

    // Length probe: report the fixed raw-signature size without touching the
    // Secure Enclave, so callers doing the standard two-call pattern don't
    // trigger two separate biometric prompts for one signature.
    if pSignature == nil {
        pulSignatureLen.pointee = CK_ULONG(ecdsaP256SignatureLength)
        return CK_RV(CKR_OK)
    }
    guard Int(pulSignatureLen.pointee) >= ecdsaP256SignatureLength else {
        pulSignatureLen.pointee = CK_ULONG(ecdsaP256SignatureLength)
        return CK_RV(CKR_BUFFER_TOO_SMALL)
    }

    defer {
        session.signObjectHandle = nil
        session.signMechanism = nil
    }

    guard let object = Pkcs11State.shared.object(handle: hKey), let blob = object.blob else {
        return CK_RV(CKR_KEY_HANDLE_INVALID)
    }
    guard let pData else { return CK_RV(CKR_ARGUMENTS_BAD) }

    let digest = Data(bytes: pData, count: Int(ulDataLen))
    guard let raw = try? SEBlob.sign(blob: blob, digest: digest), raw.count == ecdsaP256SignatureLength else {
        return CK_RV(CKR_FUNCTION_FAILED)
    }

    raw.withUnsafeBytes { pSignature!.update(from: $0.bindMemory(to: CK_BYTE.self).baseAddress!, count: raw.count) }
    pulSignatureLen.pointee = CK_ULONG(raw.count)
    return CK_RV(CKR_OK)
}
