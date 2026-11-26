import Darwin

public enum BoxKeychainDirectoryError: Error {
    case operationFailed(String, Int32)
    case unexpectedHomeOwner
}

public enum BoxKeychainDirectory {
    public static func prepare(homeDirectory: String, uid: UInt32, gid: UInt32) throws {
        let home = open(homeDirectory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard home >= 0 else { throw BoxKeychainDirectoryError.operationFailed("open home", errno) }
        defer { close(home) }
        var homeStat = stat()
        guard fstat(home, &homeStat) == 0 else {
            throw BoxKeychainDirectoryError.operationFailed("stat home", errno)
        }
        guard homeStat.st_uid == uid else { throw BoxKeychainDirectoryError.unexpectedHomeOwner }

        // Pin each directory before changing its ownership or mode. Box-controlled
        // names may be replaced while root is preparing the Keychain environment.
        let tmp = try prepareDirectory(parent: home, name: ".tmp", uid: uid, gid: gid)
        defer { close(tmp) }
        let library = try prepareDirectory(parent: home, name: "Library", uid: uid, gid: gid)
        defer { close(library) }
        let keychains = try prepareDirectory(parent: library, name: "Keychains", uid: uid, gid: gid)
        defer { close(keychains) }
        if unlinkat(keychains, "login.keychain-db", 0) != 0 && errno != ENOENT {
            throw BoxKeychainDirectoryError.operationFailed("remove prior keychain", errno)
        }
    }

    private static func prepareDirectory(parent: Int32, name: String, uid: UInt32, gid: UInt32) throws -> Int32 {
        if mkdirat(parent, name, 0o700) != 0 && errno != EEXIST {
            throw BoxKeychainDirectoryError.operationFailed("create " + name, errno)
        }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw BoxKeychainDirectoryError.operationFailed("open " + name, errno) }
        guard fchown(fd, uid, gid) == 0, fchmod(fd, 0o700) == 0 else {
            let code = errno
            close(fd)
            throw BoxKeychainDirectoryError.operationFailed("secure " + name, code)
        }
        return fd
    }
}
