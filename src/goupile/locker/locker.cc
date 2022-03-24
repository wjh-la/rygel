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

#include <Arduino.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-qualifiers"
#include <EEPROM.h>
#pragma GCC diagnostic pop

#define KEY_LEN 64

static bool error = false;
static int error_time = 0;

void setup()
{
    pinMode(13, OUTPUT);
    while (!Serial && millis() < 1000);
}

void loop()
{
    int c = Serial.read();

    if (c == 'G') {
        char key[KEY_LEN + 1];
        EEPROM.get(0, key);
        key[KEY_LEN] = 0;

        Serial.print(key);
    } else if (c == 'S') {
        char key[KEY_LEN + 1];
        int len = 0;

        while (len < KEY_LEN) {
            int c = Serial.peek();
            if (c < 0)
                continue;

            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                key[len++] = c;
                Serial.read();
            } else {
                break;
            }
        }

        if (len == KEY_LEN) {
            key[KEY_LEN] = 0;
            EEPROM.put(0, key);
        }
    } else if (c >= 0) {
        error = true;
        error_time = millis();
    }

    error &= (millis() - error_time < 2000);
    digitalWrite(13, error);
}
