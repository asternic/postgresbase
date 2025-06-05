package daos

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"database/sql"

	"github.com/AlperRehaYAZGAN/postgresbase/models"
	"github.com/AlperRehaYAZGAN/postgresbase/models/schema"
	"github.com/AlperRehaYAZGAN/postgresbase/tools/inflector"
	"github.com/AlperRehaYAZGAN/postgresbase/tools/list"
	"github.com/AlperRehaYAZGAN/postgresbase/tools/security"
	"github.com/AlperRehaYAZGAN/postgresbase/tools/tokenizer"
	"github.com/AlperRehaYAZGAN/postgresbase/tools/types"
	"github.com/pocketbase/dbx"
)

// DeleteView drops the specified view name.
//
// This method is a no-op if a view with the provided name doesn't exist.
//
// Be aware that this method is vulnerable to SQL injection and the
// "name" argument must come only from trusted input!
func (dao *Dao) DeleteView(name string) error {
	_, err := dao.DB().NewQuery(fmt.Sprintf(
		"DROP VIEW IF EXISTS {{%s}}",
		name+"bb",
	)).Execute()

	return err
}

// SaveView creates (or updates already existing) persistent SQL view.
//
// Be aware that this method is vulnerable to SQL injection and the
// "selectQuery" argument must come only from trusted input!
func (dao *Dao) SaveView(name string, selectQuery string) error {
	return dao.RunInTransaction(func(txDao *Dao) error {
		// delete old view (if exists)
		if err := txDao.DeleteView(name); err != nil {
			return err
		}

		selectQuery = strings.Trim(strings.TrimSpace(selectQuery), ";")

		// try to eagerly detect multiple inline statements
		tk := tokenizer.NewFromString(selectQuery)
		tk.Separators(';')
		if queryParts, _ := tk.ScanAll(); len(queryParts) > 1 {
			return errors.New("multiple statements are not supported")
		}

		// (re)create the view
		//
		// note: the query is wrapped in a secondary SELECT as a rudimentary
		// measure to discourage multiple inline sql statements execution.
//		viewQuery := fmt.Sprintf("CREATE VIEW {{%s}} AS SELECT * FROM (%s)", name, selectQuery)
//		viewQuery := fmt.Sprintf("CREATE VIEW {{%s}} AS SELECT * FROM (%s) AS subq", name, selectQuery)
		viewQuery := fmt.Sprintf("CREATE VIEW {{%s}} AS %s", name, selectQuery)
		if _, err := txDao.DB().NewQuery(viewQuery).Execute(); err != nil {
			return err
		}

		// fetch the view table info to ensure that the view was created
		// because missing tables or columns won't return an error
		if _, err := txDao.TableInfo(name); err != nil {
			// manually cleanup previously created view in case the func
			// is called in a nested transaction and the error is discarded
			txDao.DeleteView(name)

			return err
		}

		return nil
	})
}

func (dao *Dao) CreateViewSchema(selectQuery string) (schema.Schema, error) {
	result := schema.NewSchema()

	rootDb := dao.RootDB() // Use the Dao's own RootDB
	if rootDb == nil {
		return result, errors.New("CreateViewSchema: rootDB is not available in the current DAO context. Cannot create temporary view for schema introspection.")
	}

	// parseQueryToFields might also need the rootDb for quoting if it does complex parsing
	// For now, let's assume it can work without it or adapt it separately if needed.
	// If parseQueryToFields internally uses dao.DB() for quoting, it will also need this rootDb.
	suggestedFields, err := dao.parseQueryToFields(rootDb, selectQuery) // Pass rootDb here too
	if err != nil {
		fmt.Printf("Warning: dao.parseQueryToFields failed for view query (will rely on DB introspection): %v\n", err)
		suggestedFields = make(map[string]*queryField)
	}

	dbForQuoting := rootDb // Use the passed-in rootDb for all quoting

	txErr := dao.RunInTransaction(func(txDao *Dao) error {
		tempView := "_temp_" + strings.ToLower(security.PseudorandomString(5))
		normalizedSelectQuery := strings.Trim(strings.TrimSpace(selectQuery), ";")

		// SaveView uses txDao.DB() which is correct for execution within transaction
		if err := txDao.SaveView(tempView, normalizedSelectQuery); err != nil {
			return fmt.Errorf("failed to save temporary view %s: %w", tempView, err)
		}
		defer txDao.DeleteView(tempView)

		// Query the view using the transactional DAO's builder
		rows, err := txDao.DB().NewQuery(fmt.Sprintf("SELECT * FROM %s LIMIT 0", dbForQuoting.QuoteTableName(tempView))).Rows()
		if err != nil {
			return fmt.Errorf("failed to query temporary view %s for schema: %w", tempView, err)
		}
		defer rows.Close()
		// ... rest of the function remains the same using columnTypes ...
        columnTypes, err := rows.ColumnTypes()
        if err != nil {
            return fmt.Errorf("failed to get column types from temporary view %s: %w", tempView, err)
        }

        if len(columnTypes) == 0 {
            return fmt.Errorf("temporary view %s created but returned no columns", tempView)
        }

        fmt.Println("Columns in view (from direct query introspection):")
        for _, ct := range columnTypes {
            fmt.Printf("- %s (DB Type: %s)\n", ct.Name(), ct.DatabaseTypeName())
        }

        var hasId bool

        for _, ct := range columnTypes {
            colName := ct.Name()
            if colName == schema.FieldNameId {
                hasId = true
            }

            if _, isSuggested := suggestedFields[colName]; !isSuggested && list.ExistInSlice(colName, schema.BaseModelFieldNames()) {
                continue
            }

            var field *schema.SchemaField
            if f, ok := suggestedFields[colName]; ok && f.field != nil {
                field = f.field
                field.Name = colName
            } else {
                field = inferSchemaFieldFromDBType(ct)
            }
            result.AddField(field)
        }

        if !hasId {
            fmt.Println("Error: No ID column found in query results (from direct query introspection)")
            fmt.Println("Available columns:")
            for _, ct := range columnTypes {
                fmt.Println(ct.Name())
            }
            return errors.New("missing required id column (you can use `(ROW_NUMBER() OVER()) as id` if you don't have one)")
        }
		return nil
	})

	return result, txErr
}

// inferSchemaFieldFromDBType helper function (ensure this is defined or imported)
func inferSchemaFieldFromDBType(ct *sql.ColumnType) *schema.SchemaField {
	name := ct.Name()
	dbTypeName := strings.ToLower(ct.DatabaseTypeName())

	fieldType := schema.FieldTypeJson // Default
	var fieldOptions schema.FieldOptions = &schema.JsonOptions{MaxSize: 1024 * 1024 * 2} // Default 2MB

	switch {
	case strings.Contains(dbTypeName, "char"), // varchar, char, text
		strings.Contains(dbTypeName, "text"):
		fieldType = schema.FieldTypeText
		fieldOptions = &schema.TextOptions{}
	case strings.Contains(dbTypeName, "int"), // int2, int4, int8
		strings.Contains(dbTypeName, "serial"), // smallserial, serial, bigserial
		strings.Contains(dbTypeName, "numeric"),
		strings.Contains(dbTypeName, "decimal"),
		strings.Contains(dbTypeName, "real"),      // float4
		strings.Contains(dbTypeName, "double"): // float8
		fieldType = schema.FieldTypeNumber
		fieldOptions = &schema.NumberOptions{}
	case strings.Contains(dbTypeName, "bool"): // boolean
		fieldType = schema.FieldTypeBool
		fieldOptions = &schema.BoolOptions{}
	case strings.Contains(dbTypeName, "time"), // timestamptz, timestamp, date, time
		strings.Contains(dbTypeName, "date"):
		fieldType = schema.FieldTypeDate
		fieldOptions = &schema.DateOptions{}
	}

	return &schema.SchemaField{
		Name:    name,
		Type:    fieldType,
		Options: fieldOptions,
	}
}

// FindRecordByViewFile returns the original models.Record of the
// provided view collection file.
func (dao *Dao) FindRecordByViewFile(
	viewCollectionNameOrId string,
	fileFieldName string,
	filename string,
) (*models.Record, error) {
	view, err := dao.FindCollectionByNameOrId(viewCollectionNameOrId)
	if err != nil {
		return nil, err
	}

	if !view.IsView() {
		return nil, errors.New("not a view collection")
	}

	var findFirstNonViewQueryFileField func(int) (*queryField, error)
	findFirstNonViewQueryFileField = func(level int) (*queryField, error) {
		// check the level depth to prevent infinite circular recursion
		// (the limit is arbitrary and may change in the future)
		if level > 5 {
			return nil, errors.New("reached the max recursion level of view collection file field queries")
		}

		queryFields, err := dao.original_parseQueryToFields(view.ViewOptions().Query)
		if err != nil {
			return nil, err
		}

		for _, item := range queryFields {
			if item.collection == nil ||
				item.original == nil ||
				item.field.Name != fileFieldName {
				continue
			}

			if item.collection.IsView() {
				view = item.collection
				fileFieldName = item.original.Name
				return findFirstNonViewQueryFileField(level + 1)
			}

			return item, nil
		}

		return nil, errors.New("no query file field found")
	}

	qf, err := findFirstNonViewQueryFileField(1)
	if err != nil {
		return nil, err
	}

	cleanFieldName := inflector.Columnify(qf.original.Name)

	record := &models.Record{}

	query := dao.RecordQuery(qf.collection).Limit(1)

	if opt, ok := qf.original.Options.(schema.MultiValuer); !ok || !opt.IsMultiple() {
		query.AndWhere(dbx.HashExp{cleanFieldName: filename})
	} else {
		query.InnerJoin(fmt.Sprintf(
			`json_each(CASE WHEN json_valid([[%s]]) THEN [[%s]] ELSE json_array([[%s]]) END) as {{_je_file}}`,
			cleanFieldName, cleanFieldName, cleanFieldName,
		), dbx.HashExp{"_je_file.value": filename})
	}

	if err := query.One(record); err != nil {
		return nil, err
	}

	return record, nil
}

// -------------------------------------------------------------------
// Raw query to schema helpers
// -------------------------------------------------------------------

type queryField struct {
	// field is the final resolved field.
	field *schema.SchemaField

	// collection refers to the original field's collection model.
	// It could be nil if the found query field is not from a collection schema.
	collection *models.Collection

	// original is the original found collection field.
	// It could be nil if the found query field is not from a collection schema.
	original *schema.SchemaField
}

func defaultViewField(name string) *schema.SchemaField {
	return &schema.SchemaField{
		Name: name,
		Type: schema.FieldTypeJson,
		Options: &schema.JsonOptions{
			MaxSize: 1, // the size doesn't matter in this case
		},
	}
}

var castRegex = regexp.MustCompile(`(?i)^cast\s*\(.*\s+as\s+(\w+)\s*\)$`)

func (dao *Dao) parseQueryToFields(rootDb *dbx.DB, selectQuery string) (map[string]*queryField, error) {
	p := new(identifiersParser)
	if err := p.parse(selectQuery); err != nil {
		return nil, err
	}

	// findCollectionsByIdentifiers needs the DAO for querying _collections table
	// but if it needs quoting for table names in its own queries, it should use rootDb
	collections, err := dao.findCollectionsByIdentifiers(rootDb, p.tables)
	if err != nil {
		return nil, err
	}
    // ... rest of parseQueryToFields logic, ensure any dbx.DB method calls use rootDb if they are for quoting/metadata
    // For actual data queries (like dao.CollectionQuery used in findCollectionsByIdentifiers), it should use dao.DB()
    // The main thing is that dao.findCollectionsByIdentifiers now receives rootDb and can pass it further if needed for quoting.
    // If findCollectionsByIdentifiers itself doesn't do complex quoting and only queries, it might not need rootDb directly.
    // Let's assume for now that the main quoting need is in CreateViewSchema for the temp view name.
    // The original implementation of parseQueryToFields does not appear to use quoting functions directly on rootDb.
    // It uses dao.CollectionQuery which will use the dao's current builder (transactional or not).
    // The key is that `findCollectionsByIdentifiers` can *now* receive `rootDb` if it ever needs to do complex quoting.
    // For now, let's assume findCollectionsByIdentifiers doesn't need modification beyond signature for this specific error.
	result := make(map[string]*queryField, len(p.columns))
	var mainTable identifier
	if len(p.tables) > 0 {
		mainTable = p.tables[0]
	}

	for _, col := range p.columns {
		colLower := strings.ToLower(col.original)
		if strings.HasPrefix(colLower, "count(") || strings.HasPrefix(colLower, "total(") {
			result[col.alias] = &queryField{
				field: &schema.SchemaField{Name: col.alias, Type: schema.FieldTypeNumber},
			}
			continue
		}
		// ... (rest of the logic from your original parseQueryToFields)
		castMatch := castRegex.FindStringSubmatch(colLower)
		if len(castMatch) == 2 {
			switch castMatch[1] {
			case "real", "integer", "int", "decimal", "numeric":
				result[col.alias] = &queryField{
					field: &schema.SchemaField{Name: col.alias, Type: schema.FieldTypeNumber},
				}
				continue
			case "text":
				result[col.alias] = &queryField{
					field: &schema.SchemaField{Name: col.alias, Type: schema.FieldTypeText},
				}
				continue
			case "boolean", "bool":
				result[col.alias] = &queryField{
					field: &schema.SchemaField{Name: col.alias, Type: schema.FieldTypeBool},
				}
				continue
			}
		}
		parts := strings.Split(col.original, ".")
		var fieldName string
		var collection *models.Collection
		if len(parts) == 2 {
			fieldName = parts[1]
			collection = collections[parts[0]]
		} else {
			fieldName = parts[0]
			collection = collections[mainTable.alias]
		}
		if collection == nil {
			result[col.alias] = &queryField{field: defaultViewField(col.alias)}
			continue
		}
		if fieldName == "*" {
			return nil, errors.New("dynamic column names are not supported")
		}
		var field *schema.SchemaField
		for _, f := range collection.Schema.Fields() {
			if strings.EqualFold(f.Name, fieldName) {
				field = f
				break
			}
		}
		if field != nil {
			clone := *field
			clone.Id = ""
			clone.Name = col.alias
			result[col.alias] = &queryField{
				field:      &clone,
				collection: collection,
				original:   field,
			}
			continue
		}
		if fieldName == schema.FieldNameId {
			result[col.alias] = &queryField{
				field: &schema.SchemaField{
					Name: col.alias, Type: schema.FieldTypeRelation,
					Options: &schema.RelationOptions{MaxSelect: types.Pointer(1), CollectionId: collection.Id},
				},
				collection: collection,
			}
		} else if fieldName == schema.FieldNameCreated || fieldName == schema.FieldNameUpdated {
			result[col.alias] = &queryField{
				field:      &schema.SchemaField{Name: col.alias, Type: schema.FieldTypeDate},
				collection: collection,
			}
		} else if fieldName == schema.FieldNameUsername && collection.IsAuth() {
			result[col.alias] = &queryField{
				field:      &schema.SchemaField{Name: col.alias, Type: schema.FieldTypeText},
				collection: collection,
			}
		} else if fieldName == schema.FieldNameEmail && collection.IsAuth() {
			result[col.alias] = &queryField{
				field:      &schema.SchemaField{Name: col.alias, Type: schema.FieldTypeEmail},
				collection: collection,
			}
		} else if (fieldName == schema.FieldNameVerified || fieldName == schema.FieldNameEmailVisibility) && collection.IsAuth() {
			result[col.alias] = &queryField{
				field:      &schema.SchemaField{Name: col.alias, Type: schema.FieldTypeBool},
				collection: collection,
			}
		} else {
			result[col.alias] = &queryField{
				field:      defaultViewField(col.alias),
				collection: collection,
			}
		}
	}
	return result, nil
}

func (dao *Dao) original_parseQueryToFields(selectQuery string) (map[string]*queryField, error) {
	p := new(identifiersParser)
	if err := p.parse(selectQuery); err != nil {
		return nil, err
	}

	var rootDb *dbx.DB
	if cdb, ok := dao.ConcurrentDB().(*dbx.DB); ok {
		rootDb = cdb
	} else if dbInstance, ok := dao.DB().(*dbx.DB); ok {
		rootDb = dbInstance
	} else {
		if ncDB, ok := dao.NonconcurrentDB().(*dbx.DB); ok {
			rootDb = ncDB
		} else {
			return nil, errors.New("original_parseQueryToFields: could not obtain root *dbx.DB instance from current DAO for quoting")
		}
	}


	collections, err := dao.findCollectionsByIdentifiers(rootDb, p.tables)
	if err != nil {
		return nil, err
	}

	result := make(map[string]*queryField, len(p.columns))

	var mainTable identifier

	if len(p.tables) > 0 {
		mainTable = p.tables[0]
	}

	for _, col := range p.columns {
		colLower := strings.ToLower(col.original)

		// numeric aggregations
		if strings.HasPrefix(colLower, "count(") || strings.HasPrefix(colLower, "total(") {
			result[col.alias] = &queryField{
				field: &schema.SchemaField{
					Name: col.alias,
					Type: schema.FieldTypeNumber,
				},
			}
			continue
		}

		castMatch := castRegex.FindStringSubmatch(colLower)

		// numeric casts
		if len(castMatch) == 2 {
			switch castMatch[1] {
			case "real", "integer", "int", "decimal", "numeric":
				result[col.alias] = &queryField{
					field: &schema.SchemaField{
						Name: col.alias,
						Type: schema.FieldTypeNumber,
					},
				}
				continue
			case "text":
				result[col.alias] = &queryField{
					field: &schema.SchemaField{
						Name: col.alias,
						Type: schema.FieldTypeText,
					},
				}
				continue
			case "boolean", "bool":
				result[col.alias] = &queryField{
					field: &schema.SchemaField{
						Name: col.alias,
						Type: schema.FieldTypeBool,
					},
				}
				continue
			}
		}

		parts := strings.Split(col.original, ".")

		var fieldName string
		var collection *models.Collection

		if len(parts) == 2 {
			fieldName = parts[1]
			collection = collections[parts[0]]
		} else {
			fieldName = parts[0]
			collection = collections[mainTable.alias]
		}

		// fallback to the default field if the found column is not from a collection schema
		if collection == nil {
			result[col.alias] = &queryField{
				field: defaultViewField(col.alias),
			}
			continue
		}

		if fieldName == "*" {
			return nil, errors.New("dynamic column names are not supported")
		}

		// find the first field by name (case insensitive)
		var field *schema.SchemaField
		for _, f := range collection.Schema.Fields() {
			if strings.EqualFold(f.Name, fieldName) {
				field = f
				break
			}
		}

		if field != nil {
			clone := *field
			clone.Id = "" // unset to prevent duplications if the same field is aliased multiple times
			clone.Name = col.alias
			result[col.alias] = &queryField{
				field:      &clone,
				collection: collection,
				original:   field,
			}
			continue
		}

		if fieldName == schema.FieldNameId {
			// convert to relation since it is a direct id reference
			result[col.alias] = &queryField{
				field: &schema.SchemaField{
					Name: col.alias,
					Type: schema.FieldTypeRelation,
					Options: &schema.RelationOptions{
						MaxSelect:    types.Pointer(1),
						CollectionId: collection.Id,
					},
				},
				collection: collection,
			}
		} else if fieldName == schema.FieldNameCreated || fieldName == schema.FieldNameUpdated {
			result[col.alias] = &queryField{
				field: &schema.SchemaField{
					Name: col.alias,
					Type: schema.FieldTypeDate,
				},
				collection: collection,
			}
		} else if fieldName == schema.FieldNameUsername && collection.IsAuth() {
			result[col.alias] = &queryField{
				field: &schema.SchemaField{
					Name: col.alias,
					Type: schema.FieldTypeText,
				},
				collection: collection,
			}
		} else if fieldName == schema.FieldNameEmail && collection.IsAuth() {
			result[col.alias] = &queryField{
				field: &schema.SchemaField{
					Name: col.alias,
					Type: schema.FieldTypeEmail,
				},
				collection: collection,
			}
		} else if (fieldName == schema.FieldNameVerified || fieldName == schema.FieldNameEmailVisibility) && collection.IsAuth() {
			result[col.alias] = &queryField{
				field: &schema.SchemaField{
					Name: col.alias,
					Type: schema.FieldTypeBool,
				},
				collection: collection,
			}
		} else {
			result[col.alias] = &queryField{
				field:      defaultViewField(col.alias),
				collection: collection,
			}
		}
	}

	return result, nil
}

func (dao *Dao) findCollectionsByIdentifiers(rootDb *dbx.DB, tables []identifier) (map[string]*models.Collection, error) {
	names := make([]any, 0, len(tables))
	for _, table := range tables {
		if strings.Contains(table.alias, "(") {
			continue
		}
		names = append(names, table.original)
	}
	if len(names) == 0 {
		return nil, nil
	}
	result := make(map[string]*models.Collection, len(names))
	collections := make([]*models.Collection, 0, len(names))
	// This query uses dao.DB() which is correct as it's fetching actual data
	err := dao.CollectionQuery().AndWhere(dbx.In("name", names...)).All(&collections)
	if err != nil {
		return nil, err
	}
	for _, table := range tables {
		for _, collection := range collections {
			if collection.Name == table.original {
				result[table.alias] = collection
			}
		}
	}
	return result, nil
}

func (dao *Dao) original_findCollectionsByIdentifiers(tables []identifier) (map[string]*models.Collection, error) {
	names := make([]any, 0, len(tables))

	for _, table := range tables {
		if strings.Contains(table.alias, "(") {
			continue // skip expressions
		}
		names = append(names, table.original)
	}

	if len(names) == 0 {
		return nil, nil
	}

	result := make(map[string]*models.Collection, len(names))
	collections := make([]*models.Collection, 0, len(names))

	err := dao.CollectionQuery().
		AndWhere(dbx.In("name", names...)).
		All(&collections)
	if err != nil {
		return nil, err
	}

	for _, table := range tables {
		for _, collection := range collections {
			if collection.Name == table.original {
				result[table.alias] = collection
			}
		}
	}

	return result, nil
}

// -------------------------------------------------------------------
// Raw query identifiers parser
// -------------------------------------------------------------------

var joinReplaceRegex = regexp.MustCompile(`(?im)\s+(inner join|outer join|left join|right join|join)\s+?`)
var discardReplaceRegex = regexp.MustCompile(`(?im)\s+(where|group by|having|order|limit|with)\s+?`)
var commentsReplaceRegex = regexp.MustCompile(`(?m)(\/\*[\s\S]+\*\/)|(--.+$)`)

type identifier struct {
	original string
	alias    string
}

type identifiersParser struct {
	columns []identifier
	tables  []identifier
}

func (p *identifiersParser) parse(selectQuery string) error {
	str := strings.Trim(strings.TrimSpace(selectQuery), ";")
	str = joinReplaceRegex.ReplaceAllString(str, " _join_ ")
	str = discardReplaceRegex.ReplaceAllString(str, " _discard_ ")
	str = commentsReplaceRegex.ReplaceAllString(str, "")

	tk := tokenizer.NewFromString(str)
	tk.Separators(',', ' ', '\n', '\t')
	tk.KeepSeparator(true)

	var skip bool
	var partType string
	var activeBuilder *strings.Builder
	var selectParts strings.Builder
	var fromParts strings.Builder
	var joinParts strings.Builder

	for {
		token, err := tk.Scan()
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}

		trimmed := strings.ToLower(strings.TrimSpace(token))

		switch trimmed {
		case "select":
			skip = false
			partType = "select"
			activeBuilder = &selectParts
		case "distinct":
			continue // ignore as it is not important for the identifiers parsing
		case "from":
			skip = false
			partType = "from"
			activeBuilder = &fromParts
		case "_join_":
			skip = false

			// the previous part was also a join
			if partType == "join" {
				joinParts.WriteString(",")
			}

			partType = "join"
			activeBuilder = &joinParts
		case "_discard_":
			// skip following tokens
			skip = true
		default:
			isJoin := partType == "join"

			if isJoin && trimmed == "on" {
				skip = true
			}

			if !skip && activeBuilder != nil {
				activeBuilder.WriteString(" ")
				activeBuilder.WriteString(token)
			}
		}
	}

	selects, err := extractIdentifiers(selectParts.String())
	if err != nil {
		return err
	}

	froms, err := extractIdentifiers(fromParts.String())
	if err != nil {
		return err
	}

	joins, err := extractIdentifiers(joinParts.String())
	if err != nil {
		return err
	}

	p.columns = selects
	p.tables = froms
	p.tables = append(p.tables, joins...)

	return nil
}

func extractIdentifiers(rawExpression string) ([]identifier, error) {
	rawTk := tokenizer.NewFromString(rawExpression)
	rawTk.Separators(',')

	rawIdentifiers, err := rawTk.ScanAll()
	if err != nil {
		return nil, err
	}

	result := make([]identifier, 0, len(rawIdentifiers))

	for _, rawIdentifier := range rawIdentifiers {
		tk := tokenizer.NewFromString(rawIdentifier)
		tk.Separators(' ', '\n', '\t')

		parts, err := tk.ScanAll()
		if err != nil {
			return nil, err
		}

		resolved, err := identifierFromParts(parts)
		if err != nil {
			return nil, err
		}

		result = append(result, resolved)
	}

	return result, nil
}


func identifierFromParts(parts []string) (identifier, error) {
    var result identifier

    // Handle case where parts might contain complex expressions
    if len(parts) > 3 {
        // Try to find "AS" keyword in the parts
        for i, part := range parts {
            if strings.EqualFold(part, "as") && i < len(parts)-1 {
                result.original = strings.Join(parts[:i], " ")
                result.alias = parts[i+1]
                result.original = trimRawIdentifier(result.original)
                result.alias = trimRawIdentifier(result.alias, "'")
                return result, nil
            }
        }
        return result, fmt.Errorf(`invalid identifier parts %v`, parts)
    }

    // Original logic for simple cases
    switch len(parts) {
    case 3:
        if !strings.EqualFold(parts[1], "as") {
            return result, fmt.Errorf(`invalid identifier part - expected "as", got %v`, parts[1])
        }
        result.original = parts[0]
        result.alias = parts[2]
    case 2:
        result.original = parts[0]
        result.alias = parts[1]
    case 1:
        subParts := strings.Split(parts[0], ".")
        result.original = parts[0]
        result.alias = subParts[len(subParts)-1]
    default:
        return result, fmt.Errorf(`invalid identifier parts %v`, parts)
    }

    result.original = trimRawIdentifier(result.original)
    result.alias = trimRawIdentifier(result.alias, "'")

    return result, nil
}

func old_identifierFromParts(parts []string) (identifier, error) {
	var result identifier

	switch len(parts) {
	case 3:
		if !strings.EqualFold(parts[1], "as") {
			return result, fmt.Errorf(`invalid identifier part - expected "as", got %v`, parts[1])
		}

		result.original = parts[0]
		result.alias = parts[2]
	case 2:
		result.original = parts[0]
		result.alias = parts[1]
	case 1:
		subParts := strings.Split(parts[0], ".")
		result.original = parts[0]
		result.alias = subParts[len(subParts)-1]
	default:
		return result, fmt.Errorf(`invalid identifier parts %v`, parts)
	}

	result.original = trimRawIdentifier(result.original)

	// we trim the single quote even though it is not a valid column quote character
	// because SQLite allows it if the context expects an identifier and not string literal
	// (https://www.sqlite.org/lang_keywords.html)
	result.alias = trimRawIdentifier(result.alias, "'")

	return result, nil
}

func trimRawIdentifier(rawIdentifier string, extraTrimChars ...string) string {
	trimChars := "`\"[];"
	if len(extraTrimChars) > 0 {
		trimChars += strings.Join(extraTrimChars, "")
	}

	parts := strings.Split(rawIdentifier, ".")

	for i := range parts {
		parts[i] = strings.Trim(parts[i], trimChars)
	}

	return strings.Join(parts, ".")
}
