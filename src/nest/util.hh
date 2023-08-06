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

#pragma once

#include "src/core/libcc/libcc.hh"
#include "math.h"
#include "vendor/raylib/src/raylib.h"

namespace RG {

static inline float distance(Vector2 p1, Vector2 p2)
{
    float dx = p1.x - p2.x;
    float dy = p1.y - p2.y;

    return sqrt(dx * dx + dy * dy);
}

static inline Vector2 normalize(Vector2 vec)
{
    float length = sqrt(vec.x * vec.x + vec.y * vec.y);

    vec.x /= length;
    vec.y /= length;

    return vec;
}

struct CollisionInfo {
    Vector2 intersect;
    float distance;
};

static inline CollisionInfo dot2line(Vector2 p, Vector2 p1, Vector2 p2, float length)
{
    CollisionInfo ret = {};

    float dot = (((p.x - p1.x) * (p2.x - p1.x)) + ((p.y - p1.y) * (p2.y - p1.y))) / (length * length);

    ret.intersect.x = p1.x + (dot * (p2.x - p1.x));
    ret.intersect.y = p1.y + (dot * (p2.y - p1.y));
    ret.distance = distance(p, ret.intersect);

    return ret;
}

}