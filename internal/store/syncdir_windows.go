package store

// syncDir does nothing on Windows: a folder cannot be opened to be synced
// there (Access is denied), and NTFS keeps a rename in its own journal.
func syncDir(string) error { return nil }
