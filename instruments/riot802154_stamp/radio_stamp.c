/* On-radio timing capture. The scratch RIOT driver calls ota_radio_end_stamp. */
#ifdef OTA_STAMP
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "cpu.h"
#include "shell.h"

#define STAMP_CAPACITY 64

typedef struct {
    uint32_t tick;
    uint8_t direction;
    uint8_t length;
    uint8_t fcf0;
    uint8_t fcf1;
    uint8_t sequence;
    uint8_t crc_ok;
    uint8_t frame_bytes;
    uint8_t frame[125];
} radio_stamp_t;

static volatile radio_stamp_t _stamps[STAMP_CAPACITY];
static volatile unsigned _count;
static volatile unsigned _armed;

void ota_radio_end_stamp(uint32_t packetptr, uint8_t direction, uint8_t crc_ok)
{
    if (_armed) {
        unsigned i = _count;
        if (i < STAMP_CAPACITY) {
            const volatile uint8_t *frame =
                (const volatile uint8_t *)(uintptr_t)packetptr;
            _stamps[i].tick = NRF_TIMER4->CC[0];
            _stamps[i].direction = direction;
            _stamps[i].length = frame[0];
            _stamps[i].fcf0 = frame[1];
            _stamps[i].fcf1 = frame[2];
            _stamps[i].sequence = frame[3];
            _stamps[i].crc_ok = crc_ok;
            _stamps[i].frame_bytes = 0;
            if ((direction == 1 && (frame[1] & 0x07) == 0x01) ||
                (direction == 2 && (frame[1] & 0x0f) == 0x09)) {
                uint8_t size = frame[0] >= 2 ? frame[0] - 2 : 0;
                if (size > sizeof(_stamps[i].frame)) {
                    size = sizeof(_stamps[i].frame);
                }
                for (uint8_t j = 0; j < size; j++) {
                    _stamps[i].frame[j] = frame[j + 1];
                }
                _stamps[i].frame_bytes = size;
            }
            _count = i + 1;
        }
    }
}

static int _stamp_cmd(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "arm") == 0) {
        _armed = 0;
        _count = 0;
        _armed = 1;
        puts("stamp armed");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "dump") == 0) {
        _armed = 0;
        unsigned count = _count;
        printf("stamp count=%u freq=16000000\n", count);
        for (unsigned i = 0; i < count; i++) {
            printf("%u,%" PRIu32 ",%u,%u,%02x,%02x,%u,%u\n",
                   i, _stamps[i].tick, _stamps[i].direction,
                   _stamps[i].length, _stamps[i].fcf0, _stamps[i].fcf1,
                   _stamps[i].sequence, _stamps[i].crc_ok);
            if (_stamps[i].frame_bytes) {
                printf("frame,%u,", i);
                for (uint8_t j = 0; j < _stamps[i].frame_bytes; j++) {
                    printf("%02x", _stamps[i].frame[j]);
                }
                putchar('\n');
            }
        }
        return 0;
    }
    puts("usage: stamp arm|dump");
    return 1;
}

SHELL_COMMAND(stamp, "arm/dump nRF radio END cycle timestamps", _stamp_cmd);
#endif
