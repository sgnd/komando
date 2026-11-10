package dbx

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// BigQuery's schema comes from the API, not from queries: listing
// datasets and tables, and reading a table's metadata, costs nothing and
// needs no location. db schema lists the tables and views of the URL's
// dataset (or of every dataset in the project); a table asked for by name
// (TABLE in the URL's dataset, DATASET.TABLE or PROJECT.DATASET.TABLE)
// gets its columns (a STRUCT's fields as parent.child), its primary key,
// and its partitioning and clustering as indexes.

// bqMaxTables is where a listing stops.
const bqMaxTables = 10000

type bqTable struct {
	TableReference struct {
		ProjectID string `json:"projectId"`
		DatasetID string `json:"datasetId"`
		TableID   string `json:"tableId"`
	} `json:"tableReference"`
	Type             string    `json:"type"`
	NumRows          string    `json:"numRows"`
	Schema           *bqSchema `json:"schema"`
	TimePartitioning *struct {
		Type  string `json:"type"`
		Field string `json:"field"`
	} `json:"timePartitioning"`
	RangePartitioning *struct {
		Field string `json:"field"`
	} `json:"rangePartitioning"`
	Clustering *struct {
		Fields []string `json:"fields"`
	} `json:"clustering"`
	TableConstraints *struct {
		PrimaryKey *struct {
			Columns []string `json:"columns"`
		} `json:"primaryKey"`
	} `json:"tableConstraints"`
}

func bqTableType(t string) string {
	if s, ok := map[string]string{"TABLE": "table", "VIEW": "view", "MATERIALIZED_VIEW": "materialized view",
		"EXTERNAL": "external table", "SNAPSHOT": "snapshot"}[t]; ok {
		return s
	}
	return strings.ToLower(t)
}

func bigquerySchema(ctx context.Context, db *sql.DB, names []string) ([]Table, error) {
	tables := []Table{}
	err := bqWith(ctx, db, func(cn *bqConn) error {
		if len(names) == 0 {
			var err error
			tables, err = cn.c.listTables(ctx)
			return err
		}
		for _, n := range names {
			t, err := cn.c.describeTable(ctx, n)
			if err != nil {
				return err
			}
			tables = append(tables, t)
		}
		return nil
	})
	if err != nil {
		return nil, queryErr("bigquery", ctx, err)
	}
	return tables, nil
}

// listTables lists the tables of the URL's dataset, or of every dataset.
func (c *bqConnector) listTables(ctx context.Context) ([]Table, error) {
	datasets := []string{c.b.Dataset}
	if c.b.Dataset == "" {
		datasets = nil
		err := c.pages(ctx, c.projectPath()+"/datasets", func(raw *bqPage) {
			for _, d := range raw.Datasets {
				datasets = append(datasets, d.DatasetReference.DatasetID)
			}
		})
		if err != nil {
			return nil, err
		}
	}
	tables := []Table{}
	for _, ds := range datasets {
		err := c.pages(ctx, c.projectPath()+"/datasets/"+url.PathEscape(ds)+"/tables", func(raw *bqPage) {
			for _, t := range raw.Tables {
				if len(tables) < bqMaxTables {
					tables = append(tables, Table{Schema: ds, Name: t.TableReference.TableID, Type: bqTableType(t.Type)})
				}
			}
		})
		if err != nil {
			return nil, err
		}
	}
	return tables, nil
}

// bqPage is one page of datasets.list or tables.list.
type bqPage struct {
	NextPageToken string `json:"nextPageToken"`
	Datasets      []struct {
		DatasetReference struct {
			DatasetID string `json:"datasetId"`
		} `json:"datasetReference"`
	} `json:"datasets"`
	Tables []bqTable `json:"tables"`
}

// pages reads every page of a listing, up to bqMaxTables entries.
func (c *bqConnector) pages(ctx context.Context, path string, fn func(*bqPage)) error {
	q := url.Values{"maxResults": {"1000"}}
	for seen := 0; seen < bqMaxTables; {
		var p bqPage
		if err := c.call(ctx, http.MethodGet, path, q, nil, &p); err != nil {
			return err
		}
		fn(&p)
		seen += len(p.Datasets) + len(p.Tables)
		if p.NextPageToken == "" || len(p.Datasets)+len(p.Tables) == 0 {
			return nil
		}
		q.Set("pageToken", p.NextPageToken)
	}
	return nil
}

// describeTable reads one table's metadata: NAME, DATASET.NAME or
// PROJECT.DATASET.NAME, with or without `backticks`.
func (c *bqConnector) describeTable(ctx context.Context, name string) (Table, error) {
	parts := strings.Split(strings.ReplaceAll(name, "`", ""), ".")
	project, dataset := c.b.Project, c.b.Dataset
	switch len(parts) {
	case 1:
	case 2:
		dataset = parts[0]
	case 3:
		project, dataset = parts[0], parts[1]
	default:
		return Table{}, out.Usage("name a table as TABLE, DATASET.TABLE or PROJECT.DATASET.TABLE, not %q", name)
	}
	table := parts[len(parts)-1]
	if dataset == "" {
		return Table{}, out.Usage("%q has no dataset: write DATASET.%s, or add the dataset to the conn URL (bigquery://PROJECT/DATASET)", name, name)
	}
	var bt bqTable
	err := c.call(ctx, http.MethodGet, "/projects/"+url.PathEscape(project)+"/datasets/"+url.PathEscape(dataset)+"/tables/"+url.PathEscape(table), nil, nil, &bt)
	var e *bqError
	if errors.As(err, &e) && e.Status == http.StatusNotFound {
		return Table{}, out.Errf(out.ExitNotFound, "TABLE_NOT_FOUND", "run `komando db schema CONN` to list tables", "table %q not found", name)
	}
	if err != nil {
		return Table{}, err
	}
	t := Table{Schema: dataset, Name: table, Type: bqTableType(bt.Type)}
	if project != c.b.Project {
		t.Schema = project + "." + dataset
	}
	if n, err := strconv.ParseInt(bt.NumRows, 10, 64); err == nil {
		t.RowEstimate = &n
	}
	pk := map[string]bool{}
	if bt.TableConstraints != nil && bt.TableConstraints.PrimaryKey != nil {
		for _, col := range bt.TableConstraints.PrimaryKey.Columns {
			pk[col] = true
		}
	}
	if bt.Schema != nil {
		bqColumns(&t, "", bt.Schema.Fields, pk)
	}
	switch p := bt.TimePartitioning; {
	case p != nil && p.Field != "":
		t.Indexes = append(t.Indexes, Index{Name: "partition by", Definition: "PARTITION BY " + p.Type + "(" + p.Field + ")"})
	case p != nil:
		t.Indexes = append(t.Indexes, Index{Name: "partition by", Definition: "PARTITION BY " + p.Type + "(_PARTITIONTIME)"})
	case bt.RangePartitioning != nil:
		t.Indexes = append(t.Indexes, Index{Name: "partition by", Definition: "PARTITION BY RANGE_BUCKET(" + bt.RangePartitioning.Field + ")"})
	}
	if bt.Clustering != nil && len(bt.Clustering.Fields) > 0 {
		t.Indexes = append(t.Indexes, Index{Name: "cluster by", Definition: "CLUSTER BY " + strings.Join(bt.Clustering.Fields, ", ")})
	}
	return t, nil
}

// bqColumns adds fields to t, a STRUCT's own fields after it as
// parent.child.
func bqColumns(t *Table, prefix string, fields []bqField, pk map[string]bool) {
	for _, f := range fields {
		name := prefix + f.Name
		t.Columns = append(t.Columns, TableColumn{Name: name, Type: bqTypeName(f), Nullable: f.Mode != "REQUIRED", PrimaryKey: prefix == "" && pk[f.Name]})
		if len(f.Fields) > 0 {
			bqColumns(t, name+".", f.Fields, pk)
		}
	}
}
