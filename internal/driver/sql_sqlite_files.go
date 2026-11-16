package driver

// SQLiteFileWrites names the statements of sql that make SQLite write a
// file of its own choosing: ATTACH (it creates the file it attaches) and
// VACUUM ... INTO, and a call of load_extension, which loads native code.
// Strings and comments do not count.
func SQLiteFileWrites(sql string) ([]string, error) {
	_, toks, err := splitSQL(sql, dialects["sqlite"])
	if err != nil {
		return nil, err
	}
	var found []string
	for _, ts := range toks {
		vacuum := false
		for i, t := range ts {
			switch {
			case i == 0 && t.word == "ATTACH":
				found = append(found, "ATTACH")
			case t.word == "VACUUM" && i == 0:
				vacuum = true
			case vacuum && t.word == "INTO":
				found = append(found, "VACUUM INTO")
			case t.word == "LOAD_EXTENSION" || t.ident == "LOAD_EXTENSION":
				found = append(found, "load_extension")
			}
		}
	}
	return found, nil
}
