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

#include "src/core/libcc/libcc.hh"
#include "util.hh"

namespace RG {

struct Player {
    Vector2 pos;
    Vector2 speed;
    float height;
    double orientation;
    bool supported;
};

struct Wall {
    Vector2 p1;
    Vector2 p2;
    int width;
    float speed;
};

struct Arc {
    Vector2 center;
    float radius;
    float start;
    float end;
    float speed;
};

static HeapArray<Wall> walls;
static HeapArray<Arc> arcs;

static Player player;

static void InitWorld()
{
    player.pos.x = 40;
    player.pos.y = 20;
    player.height = 20;
    player.speed = {};
    player.orientation = 0.0f;

    walls.Append({ Vector2(0, 100), Vector2(400, 100), 3 });

    arcs.Append({ Vector2(500, 300), 90, 270, 405, 1 });
}

static void UpdateAll()
{
    // Player physics
    player.speed.y += 0.02f;
    if (player.supported) {
        player.speed.x = -2.0f * IsKeyDown(KEY_LEFT) +
                          2.0f * IsKeyDown(KEY_RIGHT);
        player.speed.y = 0;
    } else {
        float accel = -0.15f * IsKeyDown(KEY_LEFT) +
                       0.15f * IsKeyDown(KEY_RIGHT);

        if (accel > 0 && player.speed.x + accel < 1.0f) {
            player.speed.x += accel;
        } else if (accel < 0 && player.speed.x + accel > -1.0f) {
            player.speed.x += accel;
        }
    }
    player.pos.x += player.speed.x;
    player.pos.y += player.speed.y;

    // Jump from platorm
    if (player.supported && IsKeyDown(KEY_SPACE)) {
        player.pos.y -= 1;
        player.speed.y = -2;
        player.supported = false;
    }

    player.supported = false;

    // Supported by wall?
    if (!player.supported) {
        for (const Wall &wall: walls) {
            float length = distance(wall.p1, wall.p2);
            CollisionInfo col = dot2line(player.pos, wall.p1, wall.p2, length);
            int treshold = (wall.width + player.height) / 2;

            if (col.distance > treshold)
                continue;

            float dist1 = distance(player.pos, wall.p1);
            float dist2 = distance(player.pos, wall.p2);

            if (dist1 < length && dist2 < length) {
                player.pos.y = col.intersect.y - treshold;
                player.speed = {};
                player.supported = true;

                break;
            }
        }
    }

    // Supported by arc ?
    if (!player.supported) {
        for (const Arc &arc: arcs) {
            float dist = distance(player.pos, arc.center);

            if (dist < arc.radius || dist > arc.radius + player.height)
                continue;

            float start = arc.start;
            float end = arc.end;

            float angle = atan2f(arc.center.y - player.pos.y, player.pos.x - arc.center.x);
            float degrees = 90 - angle * RAD2DEG;

            if (end < start)
                end += 360;
            if (degrees < 0)
                degrees += 360;

            if (degrees > start && degrees < end) {
                player.pos.x = arc.center.x + (arc.radius + player.height / 2) * cosf(angle);
                player.pos.y = arc.center.y + (arc.radius + player.height / 2) * -sinf(angle);
                player.speed = {};
                player.supported = true;

                break;
             }
        }
    }

    // Rotate arcs
    for (Arc &arc: arcs) {
        arc.start += arc.speed;
        arc.end += arc.speed;

        if (arc.start < 0) {
            arc.start += 360.0f;
        } else if (arc.start > 360) {
            arc.start -= 360.0f;
        }

        if (arc.end < 0) {
            arc.end += 360.0f;
        } else if (arc.end > 360) {
            arc.end -= 360.0f;
        }
    }
}

static void RenderAll()
{;
    ClearBackground(RAYWHITE);

    // Draw player
    {
        Rectangle shape(player.pos.x, player.pos.y, 10, player.height);
        Vector2 origin = { 5, player.height / 2 };
        DrawRectanglePro(shape, origin, player.orientation, RED);
    }

    // Draw walls
    for (const Wall &wall: walls) {
        float angle = atan2f(wall.p2.y - wall.p1.y, wall.p2.x - wall.p1.x) / DEG2RAD;
        Rectangle shape(wall.p1.x, wall.p1.y, fabsf(wall.p2.x - wall.p1.x), wall.width);

        DrawRectanglePro(shape, Vector2 { 0, wall.width / 2 }, angle, BLACK);
    }

    // Draw arcs
    for (const Arc &arc: arcs) {
        Vector2 points[256];

        for (int i = 0; i < RG_LEN(points); i++) {
            float start = arc.start;
            float end = arc.end;

            if (end < start) {
                end += 360;
            }

            float angle = start + ((float)i / RG_LEN(points)) * (end - start);

            points[i].x = arc.center.x + arc.radius * cosf((90 - angle) * DEG2RAD);
            points[i].y = arc.center.y + arc.radius * -sinf((90 - angle) * DEG2RAD);
        }

        DrawLineStrip(points, RG_LEN(points), BLACK);
    }
}

int Main(int argc, char **argv)
{
    RG_CRITICAL(argc >= 1, "First argument is missing");

    InitWorld();

    InitWindow(800, 600, "Nest");
    RG_DEFER { CloseWindow(); };

    SetTargetFPS(60);

    while (!WindowShouldClose()) {
        UpdateAll();

        BeginDrawing();
        RenderAll();
        EndDrawing();
    }

    return 0;
}

}

// C++ namespaces are stupid
int main(int argc, char **argv) { return RG::RunApp(argc, argv); }
