// Package daos handles common PocketBase DB model manipulations.
//
// Think of daos as DB repository and service layer in one.
package daos

import (
	"errors"
	"fmt"
	"time"

	"github.com/AlperRehaYAZGAN/postgresbase/models"
	"github.com/pocketbase/dbx"
)

// New creates a new Dao instance using the provided dbx.Builder.
// If the builder is a *dbx.DB, it's used as the rootDB.
// If it's a *dbx.Tx, the rootDB for this specific Dao instance will be nil.
// This is generally suitable for operations within a transaction.
// For operations requiring a rootDB (like certain view schema operations),
// ensure the Dao is initialized with a *dbx.DB or via NewFromApp.
func New(db dbx.Builder) *Dao {
	var root *dbx.DB
	if d, ok := db.(*dbx.DB); ok {
		root = d
	}
	// If db is *dbx.Tx, root remains nil.
	return NewMultiDB(db, db, root)
}

// NewFromApp is a helper to create a Dao when the root *dbx.DB is definitively known (e.g. from the App).
// This is the preferred way to create DAOs at the application level.
func NewFromApp(concurrentDB, nonconcurrentDB dbx.Builder, rootDB *dbx.DB) *Dao {
	return NewMultiDB(concurrentDB, nonconcurrentDB, rootDB)
}

// NewMultiDB creates a new Dao instance with the provided dedicated
// concurrent and nonconcurrent db builders, and the root *dbx.DB instance.
// The rootDB is essential for operations that need to operate outside a transaction
// context or need to know the original connection pool (eg. some schema operations).
func NewMultiDB(concurrentDB, nonconcurrentDB dbx.Builder, rootDB *dbx.DB) *Dao {
	dao := &Dao{
		concurrentDB:      concurrentDB,
		nonconcurrentDB:   nonconcurrentDB,
		rootDB:            rootDB, // Store the provided rootDB
		MaxLockRetries:    8,
		ModelQueryTimeout: 30 * time.Second,
	}
	return dao
}

// Dao handles various db operations.
//
// You can think of Dao as a repository and service layer in one.
type Dao struct {
	// in a transaction both refer to the same *dbx.TX instance
	concurrentDB    dbx.Builder
	nonconcurrentDB dbx.Builder
	rootDB          *dbx.DB // Stores the original *dbx.DB connection pool

	// MaxLockRetries specifies the default max "database is locked" auto retry attempts.
	MaxLockRetries int

	// ModelQueryTimeout is the default max duration of a running ModelQuery().
	//
	// This field has no effect if an explicit query context is already specified.
	ModelQueryTimeout time.Duration

	// write hooks
	BeforeCreateFunc func(eventDao *Dao, m models.Model, action func() error) error
	AfterCreateFunc  func(eventDao *Dao, m models.Model) error
	BeforeUpdateFunc func(eventDao *Dao, m models.Model, action func() error) error
	AfterUpdateFunc  func(eventDao *Dao, m models.Model) error
	BeforeDeleteFunc func(eventDao *Dao, m models.Model, action func() error) error
	AfterDeleteFunc  func(eventDao *Dao, m models.Model) error
}

// DB returns the default dao db builder (*dbx.DB or *dbx.TX).
//
// Currently the default db builder is dao.concurrentDB but that may change in the future.
func (dao *Dao) DB() dbx.Builder {
	return dao.ConcurrentDB()
}

// ConcurrentDB returns the dao concurrent (aka. multiple open connections)
// db builder (*dbx.DB or *dbx.TX).
//
// In a transaction the concurrentDB and nonconcurrentDB refer to the same *dbx.TX instance.
func (dao *Dao) ConcurrentDB() dbx.Builder {
	return dao.concurrentDB
}

// NonconcurrentDB returns the dao nonconcurrent (aka. single open connection)
// db builder (*dbx.DB or *dbx.TX).
//
// In a transaction the concurrentDB and nonconcurrentDB refer to the same *dbx.TX instance.
func (dao *Dao) NonconcurrentDB() dbx.Builder {
	return dao.nonconcurrentDB
}

// RootDB returns the original *dbx.DB instance from which this Dao (or its transaction) was derived.
// This should be used for operations that need a connection pool, not a transaction,
// like creating temporary tables for schema introspection.
func (dao *Dao) RootDB() *dbx.DB {
	return dao.rootDB
}

// Clone returns a new Dao with the same configuration options as the current one.
func (dao *Dao) Clone() *Dao {
	clone := *dao
	// Pointers to functions are copied, which is fine as they are shared.
	// rootDB is also copied.
	return &clone
}

// WithoutHooks returns a new Dao with the same configuration options
// as the current one, but without create/update/delete hooks.
func (dao *Dao) WithoutHooks() *Dao {
	clone := dao.Clone()

	clone.BeforeCreateFunc = nil
	clone.AfterCreateFunc = nil
	clone.BeforeUpdateFunc = nil
	clone.AfterUpdateFunc = nil
	clone.BeforeDeleteFunc = nil
	clone.AfterDeleteFunc = nil

	return clone
}

// ModelQuery creates a new preconfigured select query with preset
// SELECT, FROM and other common fields based on the provided model.
func (dao *Dao) ModelQuery(m models.Model) *dbx.SelectQuery {
	tableName := m.TableName()

	return dao.DB().
		Select("{{" + tableName + "}}.*").
		From(tableName).
		WithBuildHook(func(query *dbx.Query) {
			query.WithExecHook(execLockRetry(dao.ModelQueryTimeout, dao.MaxLockRetries))
		})
}

// FindById finds a single db record with the specified id and
// scans the result into m.
func (dao *Dao) FindById(m models.Model, id string) error {
	return dao.ModelQuery(m).Where(dbx.HashExp{"id": id}).Limit(1).One(m)
}

type afterCallGroup struct {
	Model    models.Model
	EventDao *Dao
	Action   string
}

// RunInTransaction wraps fn into a transaction.
//
// It is safe to nest RunInTransaction calls as long as you use the txDao.
func (dao *Dao) RunInTransaction(fn func(txDao *Dao) error) error {
	// Check if already in a transaction
	if _, ok := dao.nonconcurrentDB.(*dbx.Tx); ok {
		return fn(dao)
	}

	root := dao.RootDB()
	if root == nil {
		return errors.New("RunInTransaction: rootDB is not available in the current DAO context to start a new transaction")
	}

	afterCalls := []afterCallGroup{}

	txError := root.Transactional(func(tx *dbx.Tx) error {
		// Create a new Dao for this transaction, ensuring it has the rootDB reference.
		txDao := NewMultiDB(tx, tx, root)

		txDao.MaxLockRetries = dao.MaxLockRetries
		txDao.ModelQueryTimeout = dao.ModelQueryTimeout

		if dao.BeforeCreateFunc != nil {
			txDao.BeforeCreateFunc = func(eventDao *Dao, m models.Model, action func() error) error {
				return dao.BeforeCreateFunc(eventDao, m, action)
			}
		}
		if dao.BeforeUpdateFunc != nil {
			txDao.BeforeUpdateFunc = func(eventDao *Dao, m models.Model, action func() error) error {
				return dao.BeforeUpdateFunc(eventDao, m, action)
			}
		}
		if dao.BeforeDeleteFunc != nil {
			txDao.BeforeDeleteFunc = func(eventDao *Dao, m models.Model, action func() error) error {
				return dao.BeforeDeleteFunc(eventDao, m, action)
			}
		}
		if dao.AfterCreateFunc != nil {
			txDao.AfterCreateFunc = func(eventDao *Dao, m models.Model) error {
				afterCalls = append(afterCalls, afterCallGroup{m, eventDao, "create"})
				return nil
			}
		}
		if dao.AfterUpdateFunc != nil {
			txDao.AfterUpdateFunc = func(eventDao *Dao, m models.Model) error {
				afterCalls = append(afterCalls, afterCallGroup{m, eventDao, "update"})
				return nil
			}
		}
		if dao.AfterDeleteFunc != nil {
			txDao.AfterDeleteFunc = func(eventDao *Dao, m models.Model) error {
				afterCalls = append(afterCalls, afterCallGroup{m, eventDao, "delete"})
				return nil
			}
		}

		return fn(txDao)
	})

	if txError != nil {
		return txError
	}

	var errs []error
	for _, call := range afterCalls {
		var err error
		switch call.Action {
		case "create":
			if dao.AfterCreateFunc != nil { // Check if the hook is set
				err = dao.AfterCreateFunc(dao, call.Model)
			}
		case "update":
			if dao.AfterUpdateFunc != nil { // Check if the hook is set
				err = dao.AfterUpdateFunc(dao, call.Model)
			}
		case "delete":
			if dao.AfterDeleteFunc != nil { // Check if the hook is set
				err = dao.AfterDeleteFunc(dao, call.Model)
			}
		}

		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("after transaction errors: %w", errors.Join(errs...))
	}

	return nil
}

// Delete deletes the provided model.
func (dao *Dao) Delete(m models.Model) error {
	if !m.HasId() {
		return errors.New("ID is not set")
	}

	return dao.lockRetry(func(retryDao *Dao) error {
		action := func() error {
			if err := retryDao.NonconcurrentDB().Model(m).Delete(); err != nil {
				return err
			}

			if retryDao.AfterDeleteFunc != nil {
				retryDao.AfterDeleteFunc(retryDao, m)
			}

			return nil
		}

		if retryDao.BeforeDeleteFunc != nil {
			return retryDao.BeforeDeleteFunc(retryDao, m, action)
		}

		return action()
	})
}

// Save persists the provided model in the database.
//
// If m.IsNew() is true, the method will perform a create, otherwise an update.
// To explicitly mark a model for update you can use m.MarkAsNotNew().
func (dao *Dao) Save(m models.Model) error {
	if m.IsNew() {
		return dao.lockRetry(func(retryDao *Dao) error {
			return retryDao.create(m)
		})
	}

	return dao.lockRetry(func(retryDao *Dao) error {
		return retryDao.update(m)
	})
}

func (dao *Dao) update(m models.Model) error {
	if !m.HasId() {
		return errors.New("ID is not set")
	}

	if m.GetCreated().IsZero() {
		m.RefreshCreated()
	}

	m.RefreshUpdated()

	action := func() error {
		if v, ok := any(m).(models.ColumnValueMapper); ok {
			dataMap := v.ColumnValueMap()

			_, err := dao.NonconcurrentDB().Update(
				m.TableName(),
				dataMap,
				dbx.HashExp{"id": m.GetId()},
			).Execute()

			if err != nil {
				return err
			}
		} else if err := dao.NonconcurrentDB().Model(m).Update(); err != nil {
			return err
		}

		if dao.AfterUpdateFunc != nil {
			return dao.AfterUpdateFunc(dao, m)
		}

		return nil
	}

	if dao.BeforeUpdateFunc != nil {
		return dao.BeforeUpdateFunc(dao, m, action)
	}

	return action()
}

func (dao *Dao) create(m models.Model) error {
	if !m.HasId() {
		// auto generate id
		m.RefreshId()
	}

	// mark the model as "new" since the model now always has an ID
	m.MarkAsNew()

	if m.GetCreated().IsZero() {
		m.RefreshCreated()
	}

	if m.GetUpdated().IsZero() {
		m.RefreshUpdated()
	}

	action := func() error {
		if v, ok := any(m).(models.ColumnValueMapper); ok {
			dataMap := v.ColumnValueMap()
			if _, ok := dataMap["id"]; !ok {
				dataMap["id"] = m.GetId()
			}

			_, err := dao.NonconcurrentDB().Insert(m.TableName(), dataMap).Execute()
			if err != nil {
				return err
			}
		} else if err := dao.NonconcurrentDB().Model(m).Insert(); err != nil {
			return err
		}

		// clears the "new" model flag
		m.MarkAsNotNew()

		if dao.AfterCreateFunc != nil {
			return dao.AfterCreateFunc(dao, m)
		}

		return nil
	}

	if dao.BeforeCreateFunc != nil {
		return dao.BeforeCreateFunc(dao, m, action)
	}

	return action()
}

func (dao *Dao) lockRetry(op func(retryDao *Dao) error) error {
	retryDao := dao

	return baseLockRetry(func(attempt int) error {
		if attempt == 2 {
			// assign new Dao without the before hooks to avoid triggering
			// the already fired before callbacks multiple times
			newDao := NewMultiDB(dao.concurrentDB, dao.nonconcurrentDB, dao.rootDB) // Pass rootDB
			newDao.AfterCreateFunc = dao.AfterCreateFunc
			newDao.AfterUpdateFunc = dao.AfterUpdateFunc
			newDao.AfterDeleteFunc = dao.AfterDeleteFunc
			retryDao = newDao
		}

		return op(retryDao)
	}, dao.MaxLockRetries)
}
