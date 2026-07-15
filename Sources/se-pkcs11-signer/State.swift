import CCryptoki
import Foundation

final class Session {
    let handle: CK_ULONG

    var findQuery: [Pkcs11Object] = []
    var findCursor = 0
    var findActive = false

    var signObjectHandle: CK_ULONG?
    var signMechanism: CK_ULONG?

    init(handle: CK_ULONG) {
        self.handle = handle
    }
}

/// All cryptoki entry points funnel through this single global instance,
/// matching the spec's process-wide C_Initialize/C_Finalize lifecycle.
final class Pkcs11State {
    static let shared = Pkcs11State()

    private let lock = NSLock()
    private var initialized = false
    private var nextSessionHandle: CK_ULONG = 1
    private var sessions: [CK_ULONG: Session] = [:]
    private var loggedIn = false
    private var catalog: ObjectCatalog?

    private init() {}

    func initialize() -> CK_RV {
        lock.lock(); defer { lock.unlock() }
        if initialized { return CK_RV(CKR_CRYPTOKI_ALREADY_INITIALIZED) }
        initialized = true
        catalog = ObjectCatalog.load()
        return CK_RV(CKR_OK)
    }

    func finalize() -> CK_RV {
        lock.lock(); defer { lock.unlock() }
        initialized = false
        sessions.removeAll()
        loggedIn = false
        catalog = nil
        return CK_RV(CKR_OK)
    }

    var isInitialized: Bool {
        lock.lock(); defer { lock.unlock() }
        return initialized
    }

    func objects() -> [Pkcs11Object] {
        lock.lock(); defer { lock.unlock() }
        return catalog?.objects ?? []
    }

    func object(handle: CK_ULONG) -> Pkcs11Object? {
        lock.lock(); defer { lock.unlock() }
        return catalog?.objects.first { $0.handle == handle }
    }

    func openSession() -> CK_ULONG {
        lock.lock(); defer { lock.unlock() }
        let handle = nextSessionHandle
        nextSessionHandle += 1
        sessions[handle] = Session(handle: handle)
        return handle
    }

    @discardableResult
    func closeSession(_ handle: CK_ULONG) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return sessions.removeValue(forKey: handle) != nil
    }

    func session(_ handle: CK_ULONG) -> Session? {
        lock.lock(); defer { lock.unlock() }
        return sessions[handle]
    }

    func login() -> CK_RV {
        lock.lock(); defer { lock.unlock() }
        if loggedIn { return CK_RV(CKR_USER_ALREADY_LOGGED_IN) }
        loggedIn = true
        return CK_RV(CKR_OK)
    }

    func logout() {
        lock.lock(); defer { lock.unlock() }
        loggedIn = false
    }
}
