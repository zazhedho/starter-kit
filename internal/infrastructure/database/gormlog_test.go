package database

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"gorm.io/gorm"

	"starter-kit/internal/config"
)

const boundSecret = "SECRET-VALUE"

func attachedMock(t *testing.T) (*gorm.DB, sqlmock.Sqlmock) {
	t.Helper()
	sqlDB, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectPing()
	db, pool, err := attach(sqlDB, config.Database{MaxOpenConns: 1, MaxIdleConns: 1})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	return db, mock
}

func TestGormLoggerReportsFailingQueryWithoutBoundValues(t *testing.T) {
	db, mock := attachedMock(t)
	mock.ExpectQuery("SELECT").WillReturnError(errors.New("boom"))

	mark := logs.Mark()
	var rows []map[string]any
	err := db.Raw("SELECT id FROM users WHERE name = ?", boundSecret).Scan(&rows).Error
	output := logs.Since(mark)

	if err == nil {
		t.Fatal("expected the query to fail")
	}
	if !strings.Contains(output, "SELECT id FROM users WHERE name = $1") {
		t.Errorf("log lacks the SQL with its placeholder: %q", output)
	}
	if strings.Contains(output, boundSecret) {
		t.Errorf("log contains the bound value: %q", output)
	}
	if strings.Contains(output, "/gormlog_test.go") {
		t.Errorf("log contains a local path: %q", output)
	}
	if n := strings.Count(strings.TrimSpace(output), "\n"); n != 0 {
		t.Errorf("want exactly one log line, got %d newlines: %q", n, output)
	}
}

func TestGormLoggerIsSilentForFastSuccessAndRecordNotFound(t *testing.T) {
	db, mock := attachedMock(t)
	mock.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	mock.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows([]string{"id"}))

	mark := logs.Mark()
	var row struct{ ID int }
	if err := db.Raw("SELECT id FROM users WHERE name = ?", boundSecret).Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	err := db.Table("users").Where("name = ?", boundSecret).First(&row).Error
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("err = %v, want record not found", err)
	}
	if output := logs.Since(mark); output != "" {
		t.Errorf("expected no log output, got %q", output)
	}
}

func TestGormLoggerReportsSlowQueries(t *testing.T) {
	db, mock := attachedMock(t)
	mock.ExpectQuery("SELECT").WillDelayFor(250 * time.Millisecond).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))

	mark := logs.Mark()
	var row struct{ ID int }
	if err := db.Raw("SELECT id FROM users WHERE name = ?", boundSecret).Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	output := logs.Since(mark)
	if !strings.Contains(output, "SLOW SQL") || strings.Contains(output, boundSecret) {
		t.Errorf("slow query log wrong: %q", output)
	}
}

func TestOpenConnectionCheckStaysSilent(t *testing.T) {
	sqlDB, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectPing().WillReturnError(errors.New("dial postgres://u:p-SECRET@h/db failed"))
	mock.ExpectClose()
	mark := logs.Mark()
	if _, _, err := attach(sqlDB, config.Database{MaxOpenConns: 1}); err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(logs.Since(mark), "SECRET") {
		t.Errorf("the connection check printed the driver error")
	}
}
