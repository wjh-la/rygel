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

void HandleRecordLoad(InstanceHolder *instance, const http_RequestInfo &request, http_IO *io)
{
    if (instance->config.sync_mode == SyncMode::Offline) {
        LogError("Records API is disabled in Offline mode");
        io->AttachError(403);
        return;
    }

    RetainPtr<const SessionInfo> session = GetCheckedSession(instance, request, io);
    const SessionStamp *stamp = session ? session->GetStamp(instance) : nullptr;

    if (!session) {
        LogError("User is not logged in");
        io->AttachError(401);
        return;
    }
    if (!stamp) {
        LogError("User is not allowed to load data");
        io->AttachError(403);
        return;
    }

    int64_t anchor;
    if (const char *str = request.GetQueryValue("anchor"); str) {
        if (!ParseInt(str, &anchor)) {
            io->AttachError(422);
            return;
        }
    } else {
        LogError("Missing 'userid' parameter");
        io->AttachError(422);
        return;
    }

    sq_Statement stmt;
    {
        LocalArray<char, 1024> sql;

        sql.len += Fmt(sql.TakeAvailable(), R"(SELECT e.rowid, e.ulid, e.hid, e.form, e.anchor,
                                                      e.parent_ulid, e.parent_version, f.anchor, f.version,
                                                      f.type, f.username, f.mtime, f.page, f.json FROM rec_entries e
                                               LEFT JOIN rec_fragments f ON (f.ulid = e.ulid)
                                               WHERE e.anchor >= ?1)").len;
        if (!stamp->HasPermission(UserPermission::DataLoad)) {
            sql.len += Fmt(sql.TakeAvailable(), " AND e.root_ulid IN (SELECT ulid FROM ins_claims WHERE userid = ?2)").len;
        }
        sql.len += Fmt(sql.TakeAvailable(), " ORDER BY e.rowid, f.anchor").len;

        if (!instance->db->Prepare(sql.data, &stmt))
            return;

        sqlite3_bind_int64(stmt, 1, anchor);
        sqlite3_bind_int64(stmt, 2, -session->userid);
    }

    // Export data
    http_JsonPageBuilder json;
    if (!json.Init(io))
        return;

    json.StartArray();
    if (stmt.Step()) {
        do {
            int64_t rowid = sqlite3_column_int64(stmt, 0);

            json.StartObject();

            json.Key("ulid"); json.String((const char *)sqlite3_column_text(stmt, 1));
            json.Key("hid"); switch (sqlite3_column_type(stmt, 2)) {
                case SQLITE_NULL: { json.Null(); } break;
                case SQLITE_INTEGER: { json.Int64(sqlite3_column_int64(stmt, 2)); } break;
                default: { json.String((const char *)sqlite3_column_text(stmt, 2)); } break;
            }
            json.Key("form"); json.String((const char *)sqlite3_column_text(stmt, 3));
            json.Key("anchor"); json.Int64(sqlite3_column_int64(stmt, 4));
            if (sqlite3_column_type(stmt, 5) != SQLITE_NULL) {
                json.Key("parent"); json.StartObject();
                json.Key("ulid"); json.String((const char *)sqlite3_column_text(stmt, 5));
                json.Key("version"); json.Int64(sqlite3_column_int64(stmt, 6));
                json.EndObject();
            } else {
                json.Key("parent"); json.Null();
            }

            json.Key("fragments"); json.StartArray();
            if (sqlite3_column_type(stmt, 7) != SQLITE_NULL) {
                do {
                    json.StartObject();

                    const char *type = (const char *)sqlite3_column_text(stmt, 9);

                    json.Key("anchor"); json.Int64(sqlite3_column_int64(stmt, 7));
                    json.Key("version"); json.Int64(sqlite3_column_int64(stmt, 8));
                    json.Key("type"); json.String(type);
                    json.Key("username"); json.String((const char *)sqlite3_column_text(stmt, 10));
                    json.Key("mtime"); json.String((const char *)sqlite3_column_text(stmt, 11));
                    if (TestStr(type, "save")) {
                        json.Key("page"); json.String((const char *)sqlite3_column_text(stmt, 12));
                        json.Key("values"); json.Raw((const char *)sqlite3_column_text(stmt, 13));
                    }

                    json.EndObject();
                } while (stmt.Step() && sqlite3_column_int64(stmt, 0) == rowid);
            } else {
                stmt.Step();
            }
            json.EndArray();

            json.EndObject();
        } while (stmt.IsRow());
    }
    if (!stmt.IsValid())
        return;
    json.EndArray();

    json.Finish();
}

struct SaveRecord {
    struct Fragment {
        const char *type = nullptr;
        const char *mtime = nullptr;
        const char *page = nullptr;
        Span<const char> json = {};
    };

    const char *ulid = nullptr;
    const char *hid = nullptr;
    const char *form = nullptr;
    struct {
        const char *ulid = nullptr;
        int64_t version = -1;
    } parent;
    HeapArray<Fragment> fragments;
    bool deleted = false;
};

void HandleRecordSave(InstanceHolder *instance, const http_RequestInfo &request, http_IO *io)
{
    if (instance->config.sync_mode == SyncMode::Offline) {
        LogError("Records API is disabled in Offline mode");
        io->AttachError(403);
        return;
    }

    RetainPtr<const SessionInfo> session = GetCheckedSession(instance, request, io);
    const SessionStamp *stamp = session ? session->GetStamp(instance) : nullptr;

    if (!session) {
        LogError("User is not logged in");
        io->AttachError(401);
        return;
    }
    if (!stamp || !stamp->HasPermission(UserPermission::DataSave)) {
        LogError("User is not allowed to save data");
        io->AttachError(403);
        return;
    }

    if (!session->userid) {
        RG_ASSERT(session->type == SessionType::Auto);

        session = MigrateGuestSession(*session, instance, request, io);
        if (!session)
            return;
        stamp = session->GetStamp(instance);
        if (!stamp)
            return;

        RG_ASSERT(session->userid < 0);
    }

    io->RunAsync([=]() {
        HeapArray<SaveRecord> records;

        // Parse records from JSON
        {
            StreamReader st;
            if (!io->OpenForRead(Megabytes(64), &st))
                return;
            json_Parser parser(&st, &io->allocator);

            parser.ParseArray();
            while (parser.InArray()) {
                SaveRecord *record = records.AppendDefault();

                parser.ParseObject();
                while (parser.InObject()) {
                    Span<const char> key = {};
                    parser.ParseKey(&key);

                    if (key == "form") {
                        parser.ParseString(&record->form);
                    } else if (key == "ulid") {
                        parser.ParseString(&record->ulid);
                    } else if (key == "hid") {
                        switch (parser.PeekToken()) {
                            case json_TokenType::Null: {
                                parser.ParseNull();
                                record->hid = nullptr;
                            } break;
                            case json_TokenType::Integer: {
                                int64_t value;
                                parser.ParseInt(&value);
                                record->hid = Fmt(&io->allocator, "%1", value).ptr;
                            } break;
                            default: {
                                parser.ParseString(&record->hid);
                            } break;
                        }
                    } else if (key == "parent") {
                        if (parser.PeekToken() == json_TokenType::Null) {
                            parser.ParseNull();
                            record->parent.ulid = nullptr;
                            record->parent.version = -1;
                        } else {
                            parser.ParseObject();
                            while (parser.InObject()) {
                                Span<const char> key2 = {};
                                parser.ParseKey(&key2);

                                if (key2 == "ulid") {
                                    parser.ParseString(&record->parent.ulid);
                                } else if (key2 == "version") {
                                    parser.ParseInt(&record->parent.version);
                                } else if (parser.IsValid()) {
                                    LogError("Unknown key '%1' in parent object", key2);
                                    io->AttachError(422);
                                    return;
                                }
                            }

                            if (RG_UNLIKELY(!record->parent.ulid || record->parent.version < 0)) {
                                LogError("Missing or invalid parent ULID or version");
                                io->AttachError(422);
                                return;
                            }
                        }
                    } else if (key == "fragments") {
                        parser.ParseArray();
                        while (parser.InArray()) {
                            SaveRecord::Fragment *fragment = record->fragments.AppendDefault();

                            parser.ParseObject();
                            while (parser.InObject()) {
                                Span<const char> key2 = {};
                                parser.ParseKey(&key2);

                                if (key2 == "type") {
                                    parser.ParseString(&fragment->type);
                                } else if (key2 == "mtime") {
                                    parser.ParseString(&fragment->mtime);
                                } else if (key2 == "page") {
                                    if (parser.PeekToken() == json_TokenType::Null) {
                                        parser.ParseNull();
                                        fragment->page = nullptr;
                                    } else {
                                        parser.ParseString(&fragment->page);
                                    }
                                } else if (key2 == "json") {
                                    parser.ParseString(&fragment->json);
                                } else if (parser.IsValid()) {
                                    LogError("Unknown key '%1' in fragment object", key2);
                                    io->AttachError(422);
                                    return;
                                }
                            }

                            if (RG_UNLIKELY(!fragment->type || !fragment->mtime)) {
                                LogError("Missing type or mtime in fragment object");
                                io->AttachError(422);
                                return;
                            }
                            if (RG_UNLIKELY(!TestStr(fragment->type, "save") && !TestStr(fragment->type, "delete"))) {
                                LogError("Invalid fragment type '%1'", fragment->type);
                                io->AttachError(422);
                                return;
                            }
                            if (TestStr(fragment->type, "save") && (!fragment->page || !fragment->json.IsValid())) {
                                LogError("Fragment 'save' is missing page or JSON");
                                io->AttachError(422);
                                return;
                            }
                        }
                    } else if (parser.IsValid()) {
                        LogError("Unknown key '%1' in record object", key);
                        io->AttachError(422);
                        return;
                    }
                }

                if (RG_UNLIKELY(!record->form || !record->ulid)) {
                    LogError("Missing form or ULID in record object");
                    io->AttachError(422);
                    return;
                }

                record->deleted = record->fragments.len &&
                                  TestStr(record->fragments[record->fragments.len - 1].type, "deleted");
            }
            if (!parser.IsValid()) {
                io->AttachError(422);
                return;
            }
        }

        // Save to database
        bool success = instance->db->Transaction([&]() {
            for (const SaveRecord &record: records) {
                bool updated = false;

                // Retrieve root ULID
                char root_ulid[32];
                if (record.parent.ulid) {
                    sq_Statement stmt;
                    if (!instance->db->Prepare("SELECT root_ulid FROM rec_entries WHERE ulid = ?1", &stmt))
                        return false;
                    sqlite3_bind_text(stmt, 1, record.parent.ulid, -1, SQLITE_STATIC);

                    if (!stmt.Step()) {
                        if (stmt.IsValid()) {
                            LogError("Parent record '%1' does not exist", record.parent.ulid);
                        }
                        return false;
                    }

                    CopyString((const char *)sqlite3_column_text(stmt, 0), root_ulid);
                } else {
                    CopyString(record.ulid, root_ulid);
                }

                // Reject restricted users
                if (!stamp->HasPermission(UserPermission::DataLoad)) {
                    sq_Statement stmt;
                    if (!instance->db->Prepare(R"(SELECT e.rowid, c.rowid FROM rec_entries e
                                                  LEFT JOIN ins_claims c ON (c.userid = ?1 AND c.ulid = e.ulid)
                                                  WHERE e.ulid = ?2)", &stmt))
                        return false;
                    sqlite3_bind_int64(stmt, 1, -session->userid);
                    sqlite3_bind_text(stmt, 2, root_ulid, -1, SQLITE_STATIC);

                    if (stmt.Step()) {
                        if (sqlite3_column_type(stmt, 1) != SQLITE_INTEGER) {
                            LogError("You are not allowed to alter this record");
                            return false;
                        }
                    } else if (stmt.IsValid()) {
                        if (!instance->db->Run(R"(INSERT INTO ins_claims (userid, ulid) VALUES (?1, ?2)
                                                  ON CONFLICT DO NOTHING)",
                                               -session->userid, root_ulid))
                            return false;
                    } else {
                        return false;
                    }
                }

                // Save record fragments
                int64_t anchor;
                if (record.fragments.len) {
                    for (Size i = 0; i < record.fragments.len; i++) {
                        const SaveRecord::Fragment &fragment = record.fragments[i];

                        if (!instance->db->Run(R"(INSERT INTO rec_fragments (ulid, version, type, userid, username,
                                                                             mtime, page, json)
                                                  VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                                                  ON CONFLICT DO NOTHING)",
                                              record.ulid, i + 1, fragment.type, session->userid, session->username,
                                              fragment.mtime, fragment.page, fragment.json))
                            return false;

                        if (sqlite3_changes(*instance->db)) {
                            updated = true;
                        } else {
                            LogDebug("Ignored conflicting fragment %1 for '%2'", i + 1, record.ulid);
                            continue;
                        }
                    }

                    anchor = sqlite3_last_insert_rowid(*instance->db);
                } else {
                    sq_Statement stmt;
                    if (!instance->db->Prepare("SELECT seq FROM sqlite_sequence WHERE name = 'rec_fragments'", &stmt))
                        return false;

                    if (stmt.Step()) {
                        anchor = sqlite3_column_int64(stmt, 0) + 1;
                    } else if (stmt.IsValid()) {
                        anchor = 1;
                    } else {
                        return false;
                    }

                    updated = true;
                }

                // Insert or update record entry (if needed)
                if (RG_LIKELY(updated)) {
                    if (!instance->db->Run(R"(INSERT INTO rec_entries (ulid, hid, form, parent_ulid,
                                                                       parent_version, root_ulid, anchor, deleted)
                                              VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                                              ON CONFLICT (ulid) DO UPDATE SET hid = IFNULL(excluded.hid, hid),
                                                                               anchor = excluded.anchor,
                                                                               deleted = excluded.deleted)",
                                          record.ulid, record.hid, record.form, record.parent.ulid,
                                          record.parent.version >= 0 ? sq_Binding(record.parent.version) : sq_Binding(),
                                          root_ulid, anchor, record.deleted))
                        return false;

                    if (sqlite3_changes(*instance->db) && !record.hid) {
                        int64_t rowid = sqlite3_last_insert_rowid(*instance->db);

                        sq_Statement stmt;
                        if (!instance->db->Prepare(R"(INSERT INTO rec_sequences (form, counter)
                                                      VALUES (?1, 1)
                                                      ON CONFLICT (form) DO UPDATE SET counter = counter + 1
                                                      RETURNING counter)", &stmt))
                            return false;
                        sqlite3_bind_text(stmt, 1, record.form, -1, SQLITE_STATIC);

                        if (!stmt.Step()) {
                            RG_ASSERT(!stmt.IsValid());
                            return false;
                        }

                        int64_t counter = sqlite3_column_int64(stmt, 0);

                        if (!instance->db->Run("UPDATE rec_entries SET hid = ?2 WHERE rowid = ?1",
                                               rowid, counter))
                            return false;
                    }
                }
            }

            return true;
        });
        if (!success)
            return;

        io->AttachText(200, "Done!");
    });
}

}
