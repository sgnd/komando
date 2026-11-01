package dbx

import (
	"database/sql"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

func openMySQL(_ string, _ driver.Target, _ string, _ DialFunc) (*sql.DB, error) {
	return nil, out.Errf(out.ExitUsage, "NOT_SUPPORTED", "use a postgres or sqlite conn for now", "mysql queries are not supported yet")
}

func isMySQLAuth(error) bool { return false }

func mysqlErr(err error) error { return err }

func mysqlSchema(*sql.Tx, []string) ([]Table, error) { return nil, nil }
