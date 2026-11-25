package out

import "testing"

// TestMaskSQLPasswords: the password literal after PASSWORD, ENCRYPTED
// PASSWORD or IDENTIFIED BY is hidden in output, its quotes kept, so SQL
// an agent reads (pg_stat_activity, a log, a migration file) shows no
// password. A column named password and other literals stay.
func TestMaskSQLPasswords(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"password", "ALTER USER app PASSWORD 'p4ss'", "ALTER USER app PASSWORD '[hidden]'"},
		{"encrypted password", "ALTER ROLE app WITH ENCRYPTED PASSWORD 'p4ss'", "ALTER ROLE app WITH ENCRYPTED PASSWORD '[hidden]'"},
		{"identified by", "CREATE USER app IDENTIFIED BY 'p4ss'", "CREATE USER app IDENTIFIED BY '[hidden]'"},
		{"identified with plugin by", "ALTER USER 'app'@'%' IDENTIFIED WITH mysql_native_password BY 'p4ss'",
			"ALTER USER 'app'@'%' IDENTIFIED WITH mysql_native_password BY '[hidden]'"},
		{"double quotes", `CREATE USER app IDENTIFIED BY "p4ss"`, `CREATE USER app IDENTIFIED BY "[hidden]"`},
		{"doubled quote", "ALTER USER app PASSWORD 'it''s'", "ALTER USER app PASSWORD '[hidden]'"},
		{"dollar quotes", "ALTER USER app PASSWORD $$p4ss$$", "ALTER USER app PASSWORD $$[hidden]$$"},
		{"tagged dollar quotes", "ALTER USER app PASSWORD $pw$p4ss$pw$", "ALTER USER app PASSWORD $pw$[hidden]$pw$"},
		{"lower case", "alter user app password 'p4ss'", "alter user app password '[hidden]'"},
		{"comment before the literal", "ALTER USER app PASSWORD /* c */ 'p4ss'", "ALTER USER app PASSWORD /* c */ '[hidden]'"},
		{"escape string", "ALTER USER app PASSWORD E'p4ss'", "ALTER USER app PASSWORD E'[hidden]'"},
		{"set password for", "SET PASSWORD FOR 'a'@'%' = 'p4ss'", "SET PASSWORD FOR 'a'@'%' = '[hidden]'"},
		{"password function", "SET PASSWORD = PASSWORD('p4ss')", "SET PASSWORD = PASSWORD('[hidden]')"},
		{"sql server", "CREATE LOGIN bob WITH PASSWORD = N'p4ss'", "CREATE LOGIN bob WITH PASSWORD = N'[hidden]'"},
		{"column named password", "SELECT password FROM users WHERE id = 1", "SELECT password FROM users WHERE id = 1"},
		{"column then a literal", "SELECT name, password, 'x' FROM users", "SELECT name, password, 'x' FROM users"},
		{"null password", "CREATE USER x WITH PASSWORD NULL", "CREATE USER x WITH PASSWORD NULL"},
		{"a word in a literal", "select * from users where name = 'password'", "select * from users where name = 'password'"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := MaskSecrets(c.in); got != c.want {
				t.Errorf("MaskSecrets(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestMaskSQLPasswordsLeavesOtherForms: forms the other maskers own keep
// their result.
func TestMaskSQLPasswordsLeavesOtherForms(t *testing.T) {
	for in, want := range map[string]string{
		`{"password": "p4ss"}`: `{"password": "[hidden]"}`,
		"password=p4ss":        "password=[hidden]",
		`password = "p4ss"`:    `password = "[hidden]"`,
	} {
		if got := MaskSecrets(in); got != want {
			t.Errorf("MaskSecrets(%q) = %q, want %q", in, got, want)
		}
	}
}
