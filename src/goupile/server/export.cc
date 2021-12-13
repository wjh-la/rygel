// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see https://www.gnu.org/licenses/.

#include "../../core/libcc/libcc.hh"
#include "domain.hh"
#include "goupile.hh"
#include "instance.hh"
#include "session.hh"
#include "../../core/libwrap/json.hh"

namespace RG {

struct ColumnInfo {
    enum class Type {
        Unknown,
        Integer,
        Double,
        String
    };

    const char *name;

    ColumnInfo *prev;
    ColumnInfo *next;
    const char *prev_name;

    Type type;
    bool valued;

    RG_HASHTABLE_HANDLER(ColumnInfo, name);
};

struct TableInfo {
    const char *name;

    BucketArray<ColumnInfo> columns;
    HashTable<const char *, ColumnInfo *> columns_map;
    HeapArray<const ColumnInfo *> ordered_columns;
    HashSet<const char *> masked_columns;

    ColumnInfo *first_column;
    ColumnInfo *last_column;
    const char *prev_name;

    RG_HASHTABLE_HANDLER(TableInfo, name);
};

struct TableSet {
    HeapArray<TableInfo> tables;
    HashTable<const char *, const TableInfo *> tables_map;

    BlockAllocator str_alloc;
};

struct RowPair {
    const char *key;
    const char *value;
};

struct RowData {
    const char *table;
    const char *root;
    const char *ulid;
    const char *hid;

    HeapArray<RowPair> pairs;
};

struct RowSet {
    HeapArray<RowData> rows;

    BlockAllocator str_alloc;
};

class TableSetBuilder {
    // Reuse for performance
    HeapArray<char> name_buf;

    BlockAllocator str_alloc;

public:
    BucketArray<TableInfo> tables;
    HashMap<const char *, Size> tables_map;

    TableSetBuilder() {}

    bool ParseColumns(const char *form, const char *root_ulid, const char *ulid, Span<const char> json);

    void Finish(TableSet *out_set);

private:
    bool ParseColumns(json_Parser *parser, int depth, const char *form,
                      const char *root_ulid, const char *ulid, const char *prefix);

    TableInfo *GetTable(const char *name);
    ColumnInfo *GetColumn(TableInfo *table, const char *prefix, const char *key, const char *suffix);
};

static void EncodeSqlName(const char *name, HeapArray<char> *out_buf)
{
    out_buf->Append('"');
    for (Size i = 0; name[i]; i++) {
        char c = name[i];

        if (c == '"') {
            out_buf->Append("\"\"");
        } else {
            out_buf->Append(c);
        }
    }
    out_buf->Append('"');

    out_buf->Grow(1);
    out_buf->ptr[out_buf->len] = 0;
}

bool TableSetBuilder::ParseColumns(const char *form, const char *root_ulid, const char *ulid, Span<const char> json)
{
    StreamReader reader(MakeSpan((const uint8_t *)json.ptr, json.len), "<json>");
    json_Parser parser(&reader, &str_alloc);

    return ParseColumns(&parser, 0, form, root_ulid, ulid, nullptr);
}

void TableSetBuilder::Finish(TableSet *out_set)
{
    // Reorder columns
    for (TableInfo &table: tables) {
        table.ordered_columns.Clear();

        const ColumnInfo *it = table.first_column;

        while (it) {
            if (it->valued && !table.masked_columns.Find(it->name)) {
                table.ordered_columns.Append(it);
            }
            it = it->next;
        }

        TableInfo *ptr = out_set->tables.AppendDefault();
        std::swap(*ptr, table);
    }

    for (const TableInfo &table: out_set->tables) {
        out_set->tables_map.Set(&table);
    }

    std::swap(out_set->str_alloc, str_alloc);
}

bool TableSetBuilder::ParseColumns(json_Parser *parser, int depth, const char *form,
                                   const char *root_ulid, const char *ulid, const char *prefix)
{
    TableInfo *table = GetTable(form);

    parser->ParseObject();
    while (parser->InObject()) {
        Span<const char> key = {};
        parser->ParseKey(&key);

        switch (parser->PeekToken()) {
            case json_TokenType::Null: { parser->ParseNull(); } break;
            case json_TokenType::Bool: {
                bool value = false;
                parser->ParseBool(&value);

                ColumnInfo *col = GetColumn(table, prefix, key.ptr, nullptr);
                col->type = (ColumnInfo::Type)std::max((int)col->type, (int)ColumnInfo::Type::Integer);
                col->valued = true;
            } break;
            case json_TokenType::Integer: {
                int64_t value = 0;
                parser->ParseInt(&value);

                ColumnInfo *col = GetColumn(table, prefix, key.ptr, nullptr);
                col->type = (ColumnInfo::Type)std::max((int)col->type, (int)ColumnInfo::Type::Integer);
                col->valued = true;
            } break;
            case json_TokenType::Double: {
                double value = 0.0;
                parser->ParseDouble(&value);

                ColumnInfo *col = GetColumn(table, prefix, key.ptr, nullptr);
                col->type = (ColumnInfo::Type)std::max((int)col->type, (int)ColumnInfo::Type::Double);
                col->valued = true;
            } break;
            case json_TokenType::String: {
                const char *str = nullptr;
                parser->ParseString(&str);

                ColumnInfo *col = GetColumn(table, prefix, key.ptr, nullptr);
                col->type = (ColumnInfo::Type)std::max((int)col->type, (int)ColumnInfo::Type::String);
                col->valued = true;
            } break;

            case json_TokenType::StartArray: {
                table->masked_columns.Set(key.ptr);

                parser->ParseArray();
                while (parser->InArray()) {
                    switch (parser->PeekToken()) {
                        case json_TokenType::Null: { parser->ParseNull(); } break;
                        case json_TokenType::Bool: {
                            bool value = false;
                            parser->ParseBool(&value);

                            ColumnInfo *col = GetColumn(table, prefix, key.ptr, value ? "1" : "0");
                            col->type = (ColumnInfo::Type)std::max((int)col->type, (int)ColumnInfo::Type::Integer);
                            col->valued = true;
                        } break;
                        case json_TokenType::Integer: {
                            int64_t value = 0;
                            parser->ParseInt(&value);

                            char buf[64];
                            Fmt(buf, "%1", value);

                            ColumnInfo *col = GetColumn(table, prefix, key.ptr, buf);
                            col->type = (ColumnInfo::Type)std::max((int)col->type, (int)ColumnInfo::Type::Integer);
                            col->valued = true;
                        } break;
                        case json_TokenType::Double: {
                            double value = 0.0;
                            parser->ParseDouble(&value);

                            char buf[64];
                            Fmt(buf, "%1", value);

                            ColumnInfo *col = GetColumn(table, prefix, key.ptr, buf);
                            col->type = (ColumnInfo::Type)std::max((int)col->type, (int)ColumnInfo::Type::Integer);
                            col->valued = true;
                        } break;
                        case json_TokenType::String: {
                            const char *str = nullptr;
                            parser->ParseString(&str);

                            ColumnInfo *col = GetColumn(table, prefix, key.ptr, str);
                            col->type = (ColumnInfo::Type)std::max((int)col->type, (int)ColumnInfo::Type::Integer);
                            col->valued = true;
                        } break;

                        default: {
                            LogError("The exporter does not support arrays of objects");
                            return false;
                        } break;
                    }
                }
            } break;

            case json_TokenType::StartObject: {
                if (RG_UNLIKELY(depth >= 8)) {
                    LogError("Excessive nesting of objects");
                    return false;
                }

                if (key.len && std::all_of(key.begin(), key.end(), IsAsciiDigit)) {
                    const char *form2 = Fmt(&str_alloc, "%1.%2", form, prefix).ptr;
                    const char *ulid2 = Fmt(&str_alloc, "%1.%2", ulid, key).ptr;

                    if (!ParseColumns(parser, depth + 1, form2, root_ulid, ulid2, nullptr))
                        return false;
                } else if (prefix) {
                    const char *prefix2 = Fmt(&str_alloc, "%1.%2", prefix, key).ptr;

                    if (!ParseColumns(parser, depth + 1, form, root_ulid, ulid, prefix2))
                        return false;
                } else {
                    if (!ParseColumns(parser, depth + 1, form, root_ulid, ulid, key.ptr))
                        return false;
                }
            } break;

            default: {
                if (parser->IsValid()) {
                    LogError("Unexpected JSON token type for '%1'", key);
                }
                return false;
            } break;
        }
    }
    if (!parser->IsValid())
        return false;

    return true;
}

ColumnInfo *TableSetBuilder::GetColumn(TableInfo *table, const char *prefix, const char *key, const char *suffix)
{
    name_buf.RemoveFrom(0);
    if (prefix) {
        for (Size i = 0; prefix[i]; i++) {
            char c = LowerAscii(prefix[i]);
            name_buf.Append(c);
        }
        name_buf.Append('.');
    }
    for (Size i = 0; key[i]; i++) {
        char c = LowerAscii(key[i]);
        name_buf.Append(c);
    }
    if (suffix) {
        name_buf.Append('.');
        for (Size i = 0; suffix[i]; i++) {
            char c = LowerAscii(suffix[i]);
            name_buf.Append(c);
        }
    }
    name_buf.Append(0);

    ColumnInfo *col = table->columns_map.FindValue(name_buf.ptr, nullptr);

    if (!col) {
        col = table->columns.AppendDefault();
        col->name = DuplicateString(name_buf.ptr, &str_alloc).ptr;

        table->columns_map.Set(col);

        if (table->columns.len > 1) {
            if (table->prev_name) {
                ColumnInfo *it = table->columns_map.FindValue(table->prev_name, nullptr);

                if (it) {
                    ColumnInfo *next = it->next;

                    while (next) {
                        if (!next->prev_name)
                            break;
                        if (!TestStr(next->prev_name, table->prev_name))
                            break;
                        if (CmpStr(next->name, col->name) > 0)
                            break;

                        it = next;
                        next = it->next;
                    }

                    if (it->next) {
                        it->next->prev = col;
                    }
                    col->next = it->next;
                    it->next = col;
                    col->prev = it;

                    table->last_column = col->next ? table->last_column : col;
                }
            }

            if (!col->prev) {
                col->prev = table->last_column;
                table->last_column->next = col;
                table->last_column = col;
            }
        } else {
            table->first_column = col;
            table->last_column = col;
        }
    }

    col->prev_name = table->prev_name;
    table->prev_name = col->name;

    return col;
}

TableInfo *TableSetBuilder::GetTable(const char *name)
{
    Size idx = tables_map.FindValue(name, -1);

    TableInfo *table;
    if (idx >= 0) {
        table = &tables[idx];
    } else {
        table = tables.AppendDefault();
        table->name = DuplicateString(name, &str_alloc).ptr;;

        tables_map.Set(table->name, tables.len - 1);
    }

    return table;
}

static bool ExtractRows(const char *form, const char *root, const char *ulid, const char *hid,
                        Span<const char> json, RowSet *out_set)
{
    return false;
}

static bool InitTables(sq_Database *db, const TableSet &set)
{
    for (const TableInfo &table: set.tables) {
        HeapArray<char> sql;

        Fmt(&sql, "CREATE TABLE "); EncodeSqlName(table.name, &sql); Fmt(&sql, " (__ROOT TEXT, __ULID TEXT, __HID, ");
        for (const ColumnInfo *col: table.ordered_columns) {
            EncodeSqlName(col->name, &sql);
            switch (col->type) {
                case ColumnInfo::Type::Unknown: { Fmt(&sql, ", "); } break;
                case ColumnInfo::Type::Integer: { Fmt(&sql, " INTEGER, "); } break;
                case ColumnInfo::Type::Double: { Fmt(&sql, " REAL, "); } break;
                case ColumnInfo::Type::String: { Fmt(&sql, " TEXT, "); } break;
            }
        }
        sql.len -= 2;
        Fmt(&sql, ")");

        if (!db->Run(sql.ptr))
            return false;
    }

    return true;
}

static bool InsertRows(sq_Database *db, const TableSet &set, Span<const RowData> rows)
{
    // Reuse for performance
    HeapArray<char> sql;

    // Import data
    HashSet<const void *> used_tables;
    for (const RowData &row: rows) {
        sql.RemoveFrom(0);

        const TableInfo *table = set.tables_map.FindValue(row.table, nullptr);
        RG_ASSERT(table);

        Fmt(&sql, "INSERT INTO "); EncodeSqlName(table->name, &sql); Fmt(&sql, " VALUES (?1, ?2, ?3");
        for (Size i = 0; i < row.pairs.len; i++) {
            Fmt(&sql, ", ?%1", i + 4);
        }
        Fmt(&sql, ")");

        sq_Statement stmt;
        if (!db->Prepare(sql.ptr, &stmt))
            return false;

        Span<const char> ulid = SplitStr(row.ulid, '.');

        sqlite3_bind_text(stmt, 1, row.root, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, ulid.ptr, (int)ulid.len, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, row.hid, -1, SQLITE_STATIC);
        for (Size i = 0; i < row.pairs.len; i++) {
            const RowPair &pair = row.pairs[i];
            sqlite3_bind_text(stmt, (int)i + 4, pair.value, -1, SQLITE_STATIC);
        }

        if (!stmt.Run())
            return false;

        used_tables.Set(table);
    }

    // Delete unused tables
    for (const TableInfo &table: set.tables) {
        if (!used_tables.Find(&table)) {
            sql.RemoveFrom(0);

            Fmt(&sql, "DROP TABLE "); EncodeSqlName(table.name, &sql);

            if (!db->Run(sql.ptr))
                return false;
        }
    }

    return true;
}

void HandleRecordExport(InstanceHolder *instance, const http_RequestInfo &request, http_IO *io)
{
    if (instance->config.sync_mode == SyncMode::Offline) {
        LogError("Records API is disabled in Offline mode");
        io->AttachError(403);
        return;
    }

    RetainPtr<const SessionInfo> session = GetCheckedSession(instance, request, io);

    if (!session) {
        LogError("User is not logged in");
        io->AttachError(401);
        return;
    }
    if (!session->HasPermission(instance, UserPermission::DataExport)) {
        LogError("User is not allowed to export data");
        io->AttachError(403);
        return;
    }

    io->RunAsync([=]() {
        sq_Statement stmt;
        if (!instance->db->Prepare(R"(SELECT e.form, e.root_ulid, e.ulid, e.hid, f.type, f.json FROM rec_entries e
                                      INNER JOIN rec_entries r ON (r.ulid = e.root_ulid)
                                      INNER JOIN rec_fragments f ON (f.ulid = e.ulid)
                                      WHERE r.deleted = 0
                                      ORDER BY f.anchor)", &stmt))
            return;

        const char *export_filename = CreateTemporaryFile(gp_domain.config.tmp_directory, "", ".tmp", &io->allocator);
        RG_DEFER { UnlinkFile(export_filename); };

        TableSet table_set;
        {
            TableSetBuilder builder;

            while (stmt.Step()) {
                const char *form = (const char *)sqlite3_column_text(stmt, 0);
                const char *root_ulid = (const char *)sqlite3_column_text(stmt, 1);
                const char *ulid = (const char *)sqlite3_column_text(stmt, 2);
                const char *type = (const char *)sqlite3_column_text(stmt, 4);

                if (TestStr(type, "save")) {
                    Span<const char> json = MakeSpan((const char *)sqlite3_column_blob(stmt, 5),
                                                     sqlite3_column_bytes(stmt, 5));

                    if (!builder.ParseColumns(form, root_ulid, ulid, json))
                        return;
                }
            }
            if (!stmt.IsValid())
                return;

            builder.Finish(&table_set);
        }

        // Prepare database
        sq_Database db;
        if (!db.Open(export_filename, SQLITE_OPEN_READWRITE))
            return;
        if (!InitTables(&db, table_set))
            return;

        // Export values
        {
            // Reuse for performance
            RowSet row_set;

            stmt.Reset();
            do {
                for (Size i = 0; i < 100 && stmt.Step(); i++) {
                    row_set.rows.RemoveFrom(0);

                    const char *form = (const char *)sqlite3_column_text(stmt, 0);
                    const char *root = (const char *)sqlite3_column_text(stmt, 1);
                    const char *ulid = (const char *)sqlite3_column_text(stmt, 2);
                    const char *hid = (const char *)sqlite3_column_text(stmt, 3);
                    const char *type = (const char *)sqlite3_column_text(stmt, 4);

                    if (TestStr(type, "save")) {
                        Span<const char> json = MakeSpan((const char *)sqlite3_column_blob(stmt, 5),
                                                         sqlite3_column_bytes(stmt, 5));

                        if (!ExtractRows(form, root, ulid, hid, json, &row_set))
                            return;
                        if (!InsertRows(&db, table_set, row_set.rows))
                            return;
                    }
                }

                row_set.str_alloc.ReleaseAll();
            } while (stmt.IsRow());
            if (!stmt.IsValid())
                return;
        }

        // Finalize export file
        if (!db.Close())
            return;

        // Ask browser to download
        {
            int64_t time = GetUnixTime();
            const char *disposition = Fmt(&io->allocator, "attachment; filename=\"%1_%2.db\"",
                                                          instance->key, FmtTimeISO(DecomposeTime(time))).ptr;
            io->AddHeader("Content-Disposition", disposition);
        }
    });
}

}
