package daos

import (
	"fmt"

	"github.com/AlperRehaYAZGAN/postgresbase/models"
	"github.com/pocketbase/dbx"
)

// HasTable checks if a table (or view) with the provided name exists (case insensitive).
func (dao *Dao) HasTable(tableName string) bool {
	var exists bool

	// sqlite3 version
	// err := dao.DB().Select("count(*)").
	// 	From("sqlite_schema").
	// 	AndWhere(dbx.HashExp{"type": []any{"table", "view"}}).
	// 	AndWhere(dbx.NewExp("LOWER([[name]])=LOWER({:tableName})", dbx.Params{"tableName": tableName})).
	// 	Limit(1).
	// 	Row(&exists)

	// postgres version
	// !CHANGED: fetch table information from information_schema
	err := dao.DB().Select("count(*)").
		From("information_schema.tables").
		AndWhere(dbx.HashExp{"table_type": []any{"BASE TABLE", "VIEW"}}).
		AndWhere(dbx.NewExp("LOWER([[table_name]])=LOWER({:tableName})", dbx.Params{"tableName": tableName})).
		Limit(1).
		Row(&exists)

	return err == nil && exists
}

// TableColumns returns all column names of a single table by its name.
func (dao *Dao) TableColumns(tableName string) ([]string, error) {
	columns := []string{}

	// !CHANGED: sqlite pragma to postgres information_schema
	err := dao.DB().NewQuery("SELECT column_name FROM information_schema.columns WHERE table_name = {:tableName}").
		Bind(dbx.Params{"tableName": tableName}).
		Column(&columns)

	return columns, err
}

// TableInfo returns the `table_info` pragma result for the specified table.
func (dao *Dao) TableInfo(tableName string) ([]*models.TableInfoRow, error) {
	info := []*models.TableInfoRow{}

	// !CHANGED: sqlite pragma to postgres information_schema
	err := dao.DB().NewQuery("SELECT * FROM information_schema.columns WHERE table_name = {:tableName}").
		Bind(dbx.Params{"tableName": tableName}).
		All(&info)
	if err != nil {
		return nil, err
	}

	// mattn/go-sqlite3 doesn't throw an error on invalid or missing table
	// so we additionally have to check whether the loaded info result is nonempty
	if len(info) == 0 {
		return nil, fmt.Errorf("empty table info probably due to invalid or missing table %s", tableName)
	}

	return info, nil
}

// TableIndexes returns a name grouped map with all non empty index of the specified table.
//
// Note: This method doesn't return an error on nonexisting table.
func (dao *Dao) TableIndexes(tableName string) (map[string]string, error) {
	indexes := []struct {
		Name string
		Sql  string
	}{}

	err := dao.DB().Select("name", "sql").
		From("sqlite_master").
		AndWhere(dbx.NewExp("sql is not null")).
		AndWhere(dbx.HashExp{
			"type":     "index",
			"tbl_name": tableName,
		}).
		All(&indexes)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string, len(indexes))

	for _, idx := range indexes {
		result[idx.Name] = idx.Sql
	}

	return result, nil
}

// DeleteTable drops the specified table.
//
// This method is a no-op if a table with the provided name doesn't exist.
//
// Be aware that this method is vulnerable to SQL injection and the
// "tableName" argument must come only from trusted input!
func (dao *Dao) original_DeleteTable(tableName string) error {
	_, err := dao.DB().NewQuery(fmt.Sprintf(
		"DROP TABLE IF EXISTS {{%s}}",
		tableName,
	)).Execute()

	return err
}

func (dao *Dao) DeleteTable(tableName string) error {
	// For PostgreSQL, ensure table name is properly quoted.
	// dbx.Builder.QuoteTableName may not exist, use dbx.DB's method.
	// We need to access the underlying *dbx.DB for its DriverName and quoting.
	var quotedTableName string
	var isPostgres bool

	if db, ok := dao.DB().(*dbx.DB); ok {
		isPostgres = (db.DriverName() == "postgres")
		quotedTableName = db.QuoteTableName(tableName)
	} else {
		// Fallback or error if not a *dbx.DB, though usually it is.
		// For simplicity, assume direct quoting if not *dbx.DB.
		// This part might need adjustment based on how dao.DB() can be a *dbx.Tx.
		// If it's a Tx, it doesn't have DriverName directly.
		// However, the SQL syntax for DROP TABLE CASCADE is standard enough.
		quotedTableName = fmt.Sprintf(`"%s"`, tableName) // Basic quoting for pg
		// To be more robust, you'd check the driver via the dao's parent App or similar
		// but for a targeted fix where you KNOW it's postgres:
		isPostgres = true // Assuming you are on Postgres if you hit this code path from the error
	}


	sql := fmt.Sprintf("DROP TABLE IF EXISTS %s", quotedTableName)
	if isPostgres { // Only add CASCADE for PostgreSQL if needed
		sql = fmt.Sprintf("DROP TABLE IF EXISTS %s CASCADE", quotedTableName)
	}

	_, err := dao.DB().NewQuery(sql).Execute()

	return err
}

// Vacuum executes VACUUM on the current dao.DB() instance in order to
// reclaim unused db disk space.
func (dao *Dao) Vacuum() error {
	_, err := dao.DB().NewQuery("VACUUM").Execute()

	return err
}
