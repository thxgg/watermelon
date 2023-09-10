// Credit: https://github.com/tardisx/embed_tern/
package migrations

import (
	"context"
	"embed"
	"fmt"
	"io/fs"

	"github.com/gofiber/fiber/v2/log"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/tern/v2/migrate"
)

const versionTable = "schema_version"

type Migrator struct {
	migrator *migrate.Migrator
}

//go:embed *.sql
var migrationFiles embed.FS

func NewMigrator(dbDNS string) (Migrator, error) {
	conn, err := pgx.Connect(context.Background(), dbDNS)
	if err != nil {
		return Migrator{}, err
	}
	migrator, err := migrate.NewMigratorEx(
		context.Background(), conn, versionTable,
		&migrate.MigratorOptions{
			DisableTx: false,
		})
	if err != nil {
		return Migrator{}, err
	}

	migrationRoot, _ := fs.Sub(migrationFiles, ".")

	err = migrator.LoadMigrations(migrationRoot)
	if err != nil {
		return Migrator{}, err
	}

	return Migrator{
		migrator: migrator,
	}, nil
}

// Info the current migration version and the embedded maximum migration, and a textual
// representation of the migration state for informational purposes.
func (m Migrator) Info() (int32, int32, string, error) {
	version, err := m.migrator.GetCurrentVersion(context.Background())
	if err != nil {
		return 0, 0, "", err
	}
	info := ""

	var last int32
	for _, thisMigration := range m.migrator.Migrations {
		last = thisMigration.Sequence

		cur := version == thisMigration.Sequence
		indicator := "  "
		if cur {
			indicator = "->"
		}
		info = info + fmt.Sprintf(
			"%2s %3d %s\n",
			indicator,
			thisMigration.Sequence, thisMigration.Name)
	}

	return version, last, info, nil
}

// Migrate migrates the DB to the most recent version of the schema.
func (m Migrator) Migrate() error {
	log.Info("Migrating database to the latest version")
	err := m.migrator.Migrate(context.Background())
	return err
}

// MigrateTo migrates to a specific version of the schema. Use '0' to undo all migrations.
func (m Migrator) MigrateTo(ver int32) error {
	log.Infof("Migrating database to version %d", ver)
	err := m.migrator.MigrateTo(context.Background(), ver)
	return err
}
