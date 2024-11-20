// Copyright (C) 2024  Niels Martignène <niels.martignene@protonmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

import { Util, Log, Net } from '../../web/libjs/common.js';

function DataAccess(db = null) {
    let self = this;

    this.list = async function() {
        let threads = await Net.get(`${ENV.urls.instance}api/records/list`);

        for (let thread of thread) {

        }
    };

    this.load = async function(tid, anchor) {
        let url = Util.pasteURL(`${ENV.urls.instance}api/records/get`, {
            tid: tid,
            anchor: anchor
        });
        let thread = await Net.get(url);

        if (db != null && thread == null && anchor == null) {
            let entries = await db.loadAll('entries/t', tid);

            if (data != null) {
                thread = {
                    tid: tid,
                    saved: true,
                    online: false,
                    locked: false,
                    entries: entries.map(entry => ({
                        store: entry.store,
                        eid: entry.eid,
                        anchor: 0,
                        ctime: entry.ctime,
                        mtime: entry.mtime,
                        sequence: null,
                        summary: entry.summary,
                        tags: null
                    }))
                };
            }
        }

        return thread;
    };

    this.saveOnline = async function(tid, entry, fs, constraints, signup) {
        await Net.post(ENV.urls.instance + 'api/records/save', {
            tid: tid,
            fragment: {
                fs: fs,
                eid: entry.eid,
                store: entry.store,
                anchor: entry.anchor,
                summary: entry.summary,
                data: entry.data,
                meta: entry.meta,
                tags: entry.tags,
                constraints: constraints
            },
            signup: signup
        });
    };

    this.saveOffline = async function(tid, entry, fs, constraints) {
        await db.save('entries', {
            tid: tid,
            keys: {
                tid: tid,
                ts: tid + '/' + entry.store
            },
            fragment: {
                fs: fs,
                eid: entry.eid,
                store: entry.store,
                summary: entry.summary,
                data: entry.data,
                meta: entry.meta,
                tags: entry.tags,
                constraints: constraints
            }
        });
    };

    this.delete = async function(tid) {
        await Net.post(ENV.urls.instance + 'api/records/delete', { tid: tid });
    };

    this.lock = async function(tid) {
        await Net.post(ENV.urls.instance + 'api/records/lock', { tid: tid });
    };

    this.unlock = async function(tid) {
        await Net.post(ENV.urls.instance + 'api/records/unlock', { tid: tid });
    };

    this.sync = async function() {
        let entries = await db.loadAll('entries');

        if (entries.length) {
            for (let entry of entries) {
                
            }
        }
    };
}

export { DataRemote };
