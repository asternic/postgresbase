package resolvers

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/AlperRehaYAZGAN/postgresbase/models"
	"github.com/AlperRehaYAZGAN/postgresbase/models/schema"
	"github.com/AlperRehaYAZGAN/postgresbase/tools/search"
	"github.com/AlperRehaYAZGAN/postgresbase/tools/security"
	"github.com/AlperRehaYAZGAN/postgresbase/tools/inflector"
	"github.com/pocketbase/dbx"
	"github.com/spf13/cast"
)

// filter modifiers
const (
	eachModifier   string = "each"
	issetModifier  string = "isset"
	lengthModifier string = "length"
)

// list of auth filter fields that don't require join with the auth
// collection or any other extra checks to be resolved.
var plainRequestAuthFields = []string{
	"@request.auth." + schema.FieldNameId,
	"@request.auth." + schema.FieldNameCollectionId,
	"@request.auth." + schema.FieldNameCollectionName,
	"@request.auth." + schema.FieldNameUsername,
	"@request.auth." + schema.FieldNameEmail,
	"@request.auth." + schema.FieldNameEmailVisibility,
	"@request.auth." + schema.FieldNameVerified,
	"@request.auth." + schema.FieldNameCreated,
	"@request.auth." + schema.FieldNameUpdated,
}

// ensure that `search.FieldResolver` interface is implemented
var _ search.FieldResolver = (*RecordFieldResolver)(nil)

// CollectionsFinder defines a common interface for retrieving
// collections and other related models.
//
// The interface at the moment is primarily used to avoid circular
// dependency with the daos.Dao package.
type CollectionsFinder interface {
	FindCollectionByNameOrId(collectionNameOrId string) (*models.Collection, error)
}

// RecordFieldResolver defines a custom search resolver struct for
// managing Record model search fields.
//
// Usually used together with `search.Provider`.
// Example:
//
//	resolver := resolvers.NewRecordFieldResolver(
//	    app.Dao(),
//	    myCollection,
//	    &models.RequestInfo{...},
//	    true,
//	)
//	provider := search.NewProvider(resolver)
//	...
type RecordFieldResolver struct {
	dao               CollectionsFinder
	baseCollection    *models.Collection
	requestInfo       *models.RequestInfo
	staticRequestInfo map[string]any
	allowedFields     []string
	loadedCollections []*models.Collection
	joins             []*join
	allowHiddenFields bool
	db                *dbx.DB
}

// NewRecordFieldResolver creates and initializes a new `RecordFieldResolver`.
func NewRecordFieldResolver(
	dao CollectionsFinder,
	db *dbx.DB, // Add db parameter
	baseCollection *models.Collection,
	requestInfo *models.RequestInfo,
	allowHiddenFields bool,
) *RecordFieldResolver {
	r := &RecordFieldResolver{
		dao:               dao,
		db:                db, // Store the db instance
		baseCollection:    baseCollection,
		requestInfo:       requestInfo,
		allowHiddenFields: allowHiddenFields,
		joins:             []*join{},
		loadedCollections: []*models.Collection{baseCollection},
		allowedFields: []string{
			`^\w+[\w\.\:]*$`,
			`^\@request\.method$`,
			`^\@request\.auth\.[\w\.\:]*\w+$`,
			`^\@request\.data\.[\w\.\:]*\w+$`,
			`^\@request\.query\.[\w\.\:]*\w+$`,
			`^\@request\.headers\.\w+$`,
			`^\@collection\.\w+(\:\w+)?\.[\w\.\:]*\w+$`,
		},
	}
	// ... (rest of the constructor remains the same)
	r.staticRequestInfo = map[string]any{}
	if r.requestInfo != nil {
		r.staticRequestInfo["method"] = r.requestInfo.Method
		r.staticRequestInfo["query"] = r.requestInfo.Query
		r.staticRequestInfo["headers"] = r.requestInfo.Headers
		r.staticRequestInfo["data"] = r.requestInfo.Data
		r.staticRequestInfo["auth"] = nil
		if r.requestInfo.AuthRecord != nil {
			r.requestInfo.AuthRecord.IgnoreEmailVisibility(true)
			r.staticRequestInfo["auth"] = r.requestInfo.AuthRecord.PublicExport()
			r.requestInfo.AuthRecord.IgnoreEmailVisibility(false)
		}
	}

	return r
}

// NewRecordFieldResolver creates and initializes a new `RecordFieldResolver`.
func originalNewRecordFieldResolver(
	dao CollectionsFinder,
	baseCollection *models.Collection,
	requestInfo *models.RequestInfo,
	// @todo consider moving per filter basis
	allowHiddenFields bool,
) *RecordFieldResolver {
	r := &RecordFieldResolver{
		dao:               dao,
		baseCollection:    baseCollection,
		requestInfo:       requestInfo,
		allowHiddenFields: allowHiddenFields,
		joins:             []*join{},
		loadedCollections: []*models.Collection{baseCollection},
		allowedFields: []string{
			`^\w+[\w\.\:]*$`,
			`^\@request\.context$`,
			`^\@request\.method$`,
			`^\@request\.auth\.[\w\.\:]*\w+$`,
			`^\@request\.data\.[\w\.\:]*\w+$`,
			`^\@request\.query\.[\w\.\:]*\w+$`,
			`^\@request\.headers\.\w+$`,
			`^\@collection\.\w+(\:\w+)?\.[\w\.\:]*\w+$`,
		},
	}

	r.staticRequestInfo = map[string]any{}
	if r.requestInfo != nil {
		r.staticRequestInfo["context"] = r.requestInfo.Context
		r.staticRequestInfo["method"] = r.requestInfo.Method
		r.staticRequestInfo["query"] = r.requestInfo.Query
		r.staticRequestInfo["headers"] = r.requestInfo.Headers
		r.staticRequestInfo["data"] = r.requestInfo.Data
		r.staticRequestInfo["auth"] = nil
		if r.requestInfo.AuthRecord != nil {
			authData := r.requestInfo.AuthRecord.PublicExport()
			// always add the record email no matter of the emailVisibility field
			authData[schema.FieldNameEmail] = r.requestInfo.AuthRecord.Email()
			r.staticRequestInfo["auth"] = authData
		}
	}

	return r
}

// UpdateQuery implements `search.FieldResolver` interface.
//
// Conditionally updates the provided search query based on the
// resolved fields (eg. dynamically joining relations).
func (r *RecordFieldResolver) OriginalUpdateQuery(query *dbx.SelectQuery) error {
	if len(r.joins) > 0 {
		query.Distinct(true)

		for _, join := range r.joins {
			query.LeftJoin(
				(join.tableName + " " + join.tableAlias),
				join.on,
			)
		}
	}

	return nil
}


func (r *RecordFieldResolver) UpdateQuery(query *dbx.SelectQuery) error {
	// Your initial print statements for debugging
	fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	fmt.Println("!!! USING MY MODIFIED RecordFieldResolver.UpdateQuery V-Option2 !!!")
	fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

	if len(r.joins) == 0 {
		fmt.Println("DEBUG: RecordFieldResolver - No joins, no DISTINCT needed by this logic.")
		return nil
	}

	isPostgres := false
	if r.db != nil {
		isPostgres = (r.db.DriverName() == "postgres")
		fmt.Printf("DEBUG: RecordFieldResolver - isPostgres: %v\n", isPostgres)
	} else {
		fmt.Println("DEBUG: RecordFieldResolver - r.db is nil! Cannot determine if PostgreSQL.")
	}

	applyDistinct := true // Apply DISTINCT by default

	if isPostgres {
		// Check if the base collection contains any JSON or File type fields
		// If it does, we cannot safely apply `SELECT DISTINCT *` with joins.
		hasNonComparableColumn := false
		if r.baseCollection != nil && r.baseCollection.Schema.Fields() != nil {
			fmt.Printf("DEBUG: RecordFieldResolver - Base collection: %s, Schema fields count: %d\n", r.baseCollection.Name, len(r.baseCollection.Schema.Fields()))
			for _, field := range r.baseCollection.Schema.Fields() {
				fmt.Printf("DEBUG: RecordFieldResolver - Checking field: %s, Type: %s\n", field.Name, field.Type)
				if field.Type == schema.FieldTypeJson || field.Type == schema.FieldTypeFile {
					hasNonComparableColumn = true
					fmt.Printf("DEBUG: RecordFieldResolver - Found non-comparable (JSON/File) column: %s. DISTINCT * will be skipped.\n", field.Name)
					break
				}
			}
		} else {
			fmt.Println("DEBUG: RecordFieldResolver - Base collection or its schema is nil.")
		}


		if hasNonComparableColumn {
			queryInfo := query.Info()
			// Only skip DISTINCT if it's a "SELECT *" on the base table.
			// If it's an explicit list of columns already, the user is responsible.
			if len(queryInfo.Selects) == 1 && strings.HasSuffix(queryInfo.Selects[0], ".*") {
				fmt.Println("DEBUG: RecordFieldResolver - PostgreSQL with JSON/File columns and SELECT *, skipping DISTINCT.")
				applyDistinct = false
			} else {
				fmt.Println("DEBUG: RecordFieldResolver - PostgreSQL with JSON/File columns, but SELECT is not a simple *, DISTINCT will be applied (may fail if JSON/File in explicit select).")
			}
		} else {
			fmt.Println("DEBUG: RecordFieldResolver - PostgreSQL, no JSON/File columns found in base collection, DISTINCT will be applied.")
		}
	} else {
		fmt.Println("DEBUG: RecordFieldResolver - Not PostgreSQL, DISTINCT will be applied.")
	}

	builtQueryBeforeDistinct := query.Build()
	fmt.Printf("DEBUG: RecordFieldResolver - SQL before potential DISTINCT: %s \nPARAMS: %v\n", builtQueryBeforeDistinct.SQL(), builtQueryBeforeDistinct.Params())

	if applyDistinct {
		query.Distinct(true)
		fmt.Println("DEBUG: RecordFieldResolver - Applied DISTINCT.")
	} else {
		fmt.Println("DEBUG: RecordFieldResolver - Skipped DISTINCT.")
	}

	builtQueryAfterDistinct := query.Build()
	fmt.Printf("DEBUG: RecordFieldResolver - SQL after potential DISTINCT: %s \nPARAMS: %v\n", builtQueryAfterDistinct.SQL(), builtQueryAfterDistinct.Params())

	for _, join := range r.joins {
		query.LeftJoin(
			(join.tableName + " " + join.tableAlias),
			join.on,
		)
	}

	return nil
}

func (r *RecordFieldResolver) works_but_loose_attach_UpdateQuery(query *dbx.SelectQuery) error {

	if len(r.joins) == 0 {
		fmt.Println("DEBUG: RecordFieldResolver - No joins, skipping DISTINCT logic modification.")
		return nil
	}

	isPostgres := false
	if r.db != nil {
		isPostgres = (r.db.DriverName() == "postgres")
		fmt.Printf("DEBUG: RecordFieldResolver - isPostgres: %v\n", isPostgres)
	} else {
		fmt.Println("DEBUG: RecordFieldResolver - r.db is nil!")
	}

	queryInfo := query.Info()
	fmt.Printf("DEBUG: RecordFieldResolver - Original SELECT clause: %v\n", queryInfo.Selects)

	// --- Your existing logic to potentially modify query.Selects(...) ---
	if isPostgres && len(queryInfo.Selects) == 1 && strings.HasSuffix(queryInfo.Selects[0], ".*") {
		fmt.Println("DEBUG: RecordFieldResolver - Condition met to potentially replace SELECT *")
		hasJsonColumn := false
		var fieldsToSelect []string
		tableName := r.baseCollection.Name
		dbInstance := r.db

		if dbInstance == nil {
			fmt.Println("DEBUG: RecordFieldResolver - dbInstance is nil inside SELECT * replacement logic!")
		} else {
			fmt.Printf("DEBUG: RecordFieldResolver - Base collection: %s, Schema fields count: %d\n", tableName, len(r.baseCollection.Schema.Fields()))
		}

		for _, field := range r.baseCollection.Schema.Fields() {
			fmt.Printf("DEBUG: RecordFieldResolver - Checking field: %s, Type: %s\n", field.Name, field.Type)
			if field.Type == schema.FieldTypeJson || field.Type == schema.FieldTypeFile {
				hasJsonColumn = true
				fmt.Printf("DEBUG: RecordFieldResolver - Found JSON column: %s\n", field.Name)
			} else {
				if dbInstance != nil {
					fieldsToSelect = append(fieldsToSelect, fmt.Sprintf("%s.%s", dbInstance.QuoteTableName(tableName), dbInstance.QuoteSimpleColumnName(inflector.Columnify(field.Name))))
				} else {
					fieldsToSelect = append(fieldsToSelect, fmt.Sprintf("\"%s\".\"%s\"", tableName, inflector.Columnify(field.Name)))
				}
			}
		}
		fmt.Printf("DEBUG: RecordFieldResolver - hasJsonColumn: %v, fieldsToSelect after schema iteration: %v\n", hasJsonColumn, fieldsToSelect)

		if hasJsonColumn {
			// Add base model fields
			for _, baseFieldName := range schema.BaseModelFieldNames() {
				alreadyAdded := false
				quotedBaseFieldName := ""
				if dbInstance != nil {
					quotedBaseFieldName = dbInstance.QuoteSimpleColumnName(inflector.Columnify(baseFieldName))
				} else {
					quotedBaseFieldName = fmt.Sprintf("\"%s\"", inflector.Columnify(baseFieldName))
				}
				for _, selectedCol := range fieldsToSelect {
					if strings.HasSuffix(selectedCol, quotedBaseFieldName) {
						alreadyAdded = true
						break
					}
				}
				if !alreadyAdded {
					if dbInstance != nil {
						fieldsToSelect = append(fieldsToSelect, fmt.Sprintf("%s.%s", dbInstance.QuoteTableName(tableName), quotedBaseFieldName))
					} else {
						fieldsToSelect = append(fieldsToSelect, fmt.Sprintf("\"%s\".%s", tableName, quotedBaseFieldName))
					}
				}
			}
			// Add auth specific fields
			if r.baseCollection.IsAuth() {
				for _, authFieldName := range schema.AuthFieldNames() {
					alreadyAdded := false
					quotedAuthFieldName := ""
					if dbInstance != nil {
						quotedAuthFieldName = dbInstance.QuoteSimpleColumnName(inflector.Columnify(authFieldName))
					} else {
						quotedAuthFieldName = fmt.Sprintf("\"%s\"", inflector.Columnify(authFieldName))
					}

					for _, selectedCol := range fieldsToSelect {
						if strings.HasSuffix(selectedCol, quotedAuthFieldName) {
							alreadyAdded = true
							break
						}
					}
					if !alreadyAdded {
						if dbInstance != nil {
							fieldsToSelect = append(fieldsToSelect, fmt.Sprintf("%s.%s", dbInstance.QuoteTableName(tableName), quotedAuthFieldName))
						} else {
							fieldsToSelect = append(fieldsToSelect, fmt.Sprintf("\"%s\".%s", tableName, quotedAuthFieldName))
						}
					}
				}
			}

			if len(fieldsToSelect) > 0 {
				fmt.Printf("DEBUG: RecordFieldResolver - Replacing SELECT * with explicit columns: %v\n", fieldsToSelect)
				query.Select(fieldsToSelect...)
			} else {
				fmt.Println("DEBUG: RecordFieldResolver - All fields are JSON or no comparable fields, falling back to SELECT id.")
				if dbInstance != nil {
					query.Select(fmt.Sprintf("%s.id", dbInstance.QuoteTableName(tableName)))
				} else {
					query.Select(fmt.Sprintf("\"%s\".id", tableName))
				}
			}
		} else {
			fmt.Println("DEBUG: RecordFieldResolver - No JSON columns found, SELECT * will not be replaced for DISTINCT.")
		}
	} else {
		// ... (your existing else conditions for logging why SELECT * wasn't replaced)
		if !isPostgres {
			fmt.Println("DEBUG: RecordFieldResolver - Not a PostgreSQL instance.")
		}
		if len(queryInfo.Selects) != 1 || !strings.HasSuffix(queryInfo.Selects[0], ".*") {
			fmt.Printf("DEBUG: RecordFieldResolver - SELECT clause is not a simple SELECT * (len: %d, clause: %v).\n", len(queryInfo.Selects), queryInfo.Selects)
		}
	}
	// --- End of your existing logic to potentially modify query.Selects(...) ---

	// Build the query to get SQL and Params for debugging
	builtQuery := query.Build()
	fmt.Printf("DEBUG: RecordFieldResolver - SQL before DISTINCT: %s \nPARAMS: %v\n", builtQuery.SQL(), builtQuery.Params())

	query.Distinct(true)

	// Build again to see the effect of DISTINCT
	builtQueryAfterDistinct := query.Build()
	fmt.Printf("DEBUG: RecordFieldResolver - SQL after DISTINCT: %s \nPARAMS: %v\n", builtQueryAfterDistinct.SQL(), builtQueryAfterDistinct.Params())

	for _, join := range r.joins {
		query.LeftJoin(
			(join.tableName + " " + join.tableAlias),
			join.on,
		)
	}

	return nil
}

// Resolve implements `search.FieldResolver` interface.
//
// Example of some resolvable fieldName formats:
//
//	id
//	someSelect.each
//	project.screen.status
//	screen.project_via_prototype.name
//	@request.context
//	@request.method
//	@request.query.filter
//	@request.headers.x_token
//	@request.auth.someRelation.name
//	@request.data.someRelation.name
//	@request.data.someField
//	@request.data.someSelect:each
//	@request.data.someField:isset
//	@collection.product.name
func (r *RecordFieldResolver) Resolve(fieldName string) (*search.ResolverResult, error) {
	return parseAndRun(fieldName, r)
}

func (r *RecordFieldResolver) resolveStaticRequestField(path ...string) (*search.ResolverResult, error) {
	if len(path) == 0 {
		return nil, fmt.Errorf("at least one path key should be provided")
	}

	lastProp, modifier, err := splitModifier(path[len(path)-1])
	if err != nil {
		return nil, err
	}

	path[len(path)-1] = lastProp

	// extract value
	resultVal, err := extractNestedMapVal(r.staticRequestInfo, path...)

	if modifier == issetModifier {
		if err != nil {
			return &search.ResolverResult{Identifier: "FALSE"}, nil
		}
		return &search.ResolverResult{Identifier: "TRUE"}, nil
	}

	// note: we are ignoring the error because requestInfo is dynamic
	// and some of the lookup keys may not be defined for the request

	switch v := resultVal.(type) {
	case nil:
		return &search.ResolverResult{Identifier: "NULL"}, nil
	case string:
		// check if it is a number field and explicitly try to cast to
		// float in case of a numeric string value was used
		// (this usually the case when the data is from a multipart/form-data request)
		field := r.baseCollection.Schema.GetFieldByName(path[len(path)-1])
		if field != nil && field.Type == schema.FieldTypeNumber {
			if nv, err := strconv.ParseFloat(v, 64); err == nil {
				resultVal = nv
			}
		}
		// otherwise - no further processing is needed...
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		// no further processing is needed...
	default:
		// non-plain value
		// try casting to string (in case for exampe fmt.Stringer is implemented)
		val, castErr := cast.ToStringE(v)

		// if that doesn't work, try encoding it
		if castErr != nil {
			encoded, jsonErr := json.Marshal(v)
			if jsonErr == nil {
				val = string(encoded)
			}
		}

		resultVal = val
	}

	placeholder := "f" + security.PseudorandomString(5)

	return &search.ResolverResult{
		Identifier: "{:" + placeholder + "}",
		Params:     dbx.Params{placeholder: resultVal},
	}, nil
}

func (r *RecordFieldResolver) loadCollection(collectionNameOrId string) (*models.Collection, error) {
	// return already loaded
	for _, collection := range r.loadedCollections {
		if collection.Id == collectionNameOrId || strings.EqualFold(collection.Name, collectionNameOrId) {
			return collection, nil
		}
	}

	// load collection
	collection, err := r.dao.FindCollectionByNameOrId(collectionNameOrId)
	if err != nil {
		return nil, err
	}
	r.loadedCollections = append(r.loadedCollections, collection)

	return collection, nil
}

func (r *RecordFieldResolver) registerJoin(tableName string, tableAlias string, on dbx.Expression) {
	join := &join{
		tableName:  tableName,
		tableAlias: tableAlias,
		on:         on,
	}

	// replace existing join
	for i, j := range r.joins {
		if j.tableAlias == join.tableAlias {
			r.joins[i] = join
			return
		}
	}

	// register new join
	r.joins = append(r.joins, join)
}

func extractNestedMapVal(m map[string]any, keys ...string) (any, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("at least one key should be provided")
	}

	result, ok := m[keys[0]]
	if !ok {
		return nil, fmt.Errorf("invalid key path - missing key %q", keys[0])
	}

	// end key reached
	if len(keys) == 1 {
		return result, nil
	}

	if m, ok = result.(map[string]any); !ok {
		return nil, fmt.Errorf("expected map, got %#v", result)
	}

	return extractNestedMapVal(m, keys[1:]...)
}

func splitModifier(combined string) (string, string, error) {
	parts := strings.Split(combined, ":")

	if len(parts) != 2 {
		return combined, "", nil
	}

	// validate modifier
	switch parts[1] {
	case issetModifier,
		eachModifier,
		lengthModifier:
		return parts[0], parts[1], nil
	}

	return "", "", fmt.Errorf("unknown modifier in %q", combined)
}
