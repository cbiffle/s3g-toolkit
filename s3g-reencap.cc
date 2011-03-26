/*
 * Copyright 2011 Cliff L. Biffle.
 * This file is licensed under Creative Commons Attribution-ShareAlike 3.0.
 * http://creativecommons.org/licenses/by-sa/3.0/
 */

/*
 * s3g-reencap
 *
 * The S3G wire protocol -- the data exchanged between host software and a
 * bot -- is built out of self-describing packets.  In particular, each packet
 * encodes its length, so the receiver can gracefully deal with unknown command
 * types.  The S3G *file format,* however, strips off the framing and length
 * information.  Any program that wishes to process S3G files must understand
 * every posssible S3G command, if only to know how many bytes to ignore.
 *
 * This filter reconstructs the wire protocol framing.  It expects an S3G file
 * on stdin, and produces packets on stdout, framed as follows:
 *  - A start byte (0xD5)
 *  - A byte indicating the length of the command payload to follow.
 *  - The payload.
 *  - A CRC, excluded from the length calculation.
 *
 * I call the output "ES3G," for "Encapsulated S3G."
 *
 * This is the only filter in this toolkit that needs to understand *every* S3G
 * command.  (It doesn't yet understand them all -- I'm adding them as I see
 * them used in the wild.)
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// The command information stored in the table below.
struct CommandInfo {
  uint8_t id;
  const char *name;
  int length;

  bool is_known_command() const { return name != NULL; }
};

/*
 * A magic number indicating that the length may be computed as follows:
 *   length(payload) = payload[3] + 3
 */
static const int kToolActionLength = -1;

// A NULL name below means "unimplemented command."
static const CommandInfo commands[256] = {
  { 0, NULL, 0 },
  { 1, NULL, 0 },
  { 2, NULL, 0 },
  { 3, NULL, 0 },
  { 4, NULL, 0 },
  { 5, NULL, 0 },
  { 6, NULL, 0 },
  { 7, NULL, 0 },
  { 8, NULL, 0 },
  { 9, NULL, 0 },
  { 10, NULL, 0 },
  { 11, NULL, 0 },
  { 12, NULL, 0 },
  { 13, NULL, 0 },
  { 14, NULL, 0 },
  { 15, NULL, 0 },
  { 16, NULL, 0 },
  { 17, NULL, 0 },
  { 18, NULL, 0 },
  { 19, NULL, 0 },
  { 20, NULL, 0 },
  { 21, NULL, 0 },
  { 22, NULL, 0 },
  { 23, NULL, 0 },
  { 24, NULL, 0 },
  { 25, NULL, 0 },
  { 26, NULL, 0 },
  { 27, NULL, 0 },
  { 28, NULL, 0 },
  { 29, NULL, 0 },
  { 30, NULL, 0 },
  { 31, NULL, 0 },
  { 32, NULL, 0 },
  { 33, NULL, 0 },
  { 34, NULL, 0 },
  { 35, NULL, 0 },
  { 36, NULL, 0 },
  { 37, NULL, 0 },
  { 38, NULL, 0 },
  { 39, NULL, 0 },
  { 40, NULL, 0 },
  { 41, NULL, 0 },
  { 42, NULL, 0 },
  { 43, NULL, 0 },
  { 44, NULL, 0 },
  { 45, NULL, 0 },
  { 46, NULL, 0 },
  { 47, NULL, 0 },
  { 48, NULL, 0 },
  { 49, NULL, 0 },
  { 50, NULL, 0 },
  { 51, NULL, 0 },
  { 52, NULL, 0 },
  { 53, NULL, 0 },
  { 54, NULL, 0 },
  { 55, NULL, 0 },
  { 56, NULL, 0 },
  { 57, NULL, 0 },
  { 58, NULL, 0 },
  { 59, NULL, 0 },
  { 60, NULL, 0 },
  { 61, NULL, 0 },
  { 62, NULL, 0 },
  { 63, NULL, 0 },
  { 64, NULL, 0 },
  { 65, NULL, 0 },
  { 66, NULL, 0 },
  { 67, NULL, 0 },
  { 68, NULL, 0 },
  { 69, NULL, 0 },
  { 70, NULL, 0 },
  { 71, NULL, 0 },
  { 72, NULL, 0 },
  { 73, NULL, 0 },
  { 74, NULL, 0 },
  { 75, NULL, 0 },
  { 76, NULL, 0 },
  { 77, NULL, 0 },
  { 78, NULL, 0 },
  { 79, NULL, 0 },
  { 80, NULL, 0 },
  { 81, NULL, 0 },
  { 82, NULL, 0 },
  { 83, NULL, 0 },
  { 84, NULL, 0 },
  { 85, NULL, 0 },
  { 86, NULL, 0 },
  { 87, NULL, 0 },
  { 88, NULL, 0 },
  { 89, NULL, 0 },
  { 90, NULL, 0 },
  { 91, NULL, 0 },
  { 92, NULL, 0 },
  { 93, NULL, 0 },
  { 94, NULL, 0 },
  { 95, NULL, 0 },
  { 96, NULL, 0 },
  { 97, NULL, 0 },
  { 98, NULL, 0 },
  { 99, NULL, 0 },
  { 100, NULL, 0 },
  { 101, NULL, 0 },
  { 102, NULL, 0 },
  { 103, NULL, 0 },
  { 104, NULL, 0 },
  { 105, NULL, 0 },
  { 106, NULL, 0 },
  { 107, NULL, 0 },
  { 108, NULL, 0 },
  { 109, NULL, 0 },
  { 110, NULL, 0 },
  { 111, NULL, 0 },
  { 112, NULL, 0 },
  { 113, NULL, 0 },
  { 114, NULL, 0 },
  { 115, NULL, 0 },
  { 116, NULL, 0 },
  { 117, NULL, 0 },
  { 118, NULL, 0 },
  { 119, NULL, 0 },
  { 120, NULL, 0 },
  { 121, NULL, 0 },
  { 122, NULL, 0 },
  { 123, NULL, 0 },
  { 124, NULL, 0 },
  { 125, NULL, 0 },
  { 126, NULL, 0 },
  { 127, NULL, 0 },
  { 128, NULL, 0 },
  { 129, "QUEUE_POINT", 16 },
  { 130, "SET_POSITION", 12 },
  { 131, "FIND_MINS", 7 },
  { 132, "FIND_MAXS", 7 },
  { 133, "DELAY", 4 },
  { 134, "CHANGE_TOOL", 1 },
  { 135, "WAIT_FOR_TOOL_READY", 5 },
  { 136, "TOOL_ACTION", kToolActionLength },
  { 137, "ENABLE_DISABLE_AXES", 1 },
  { 138, "USER_BLOCK", 2 },
  { 139, "QUEUE_POINT_EXT", 24 },
  { 140, "SET_POSITION_EXT", 20 },
  { 141, "WAIT_FOR_PLATFORM_READY", 5 },
  { 142, "QUEUE_POINT_EXT_NEW", 25 },
  { 143, "STORE_HOME", 1 },
  { 144, "RECALL_HOME", 1 },
  { 145, NULL, 0 },
  { 146, NULL, 0 },
  { 147, NULL, 0 },
  { 148, NULL, 0 },
  { 149, NULL, 0 },
  { 150, NULL, 0 },
  { 151, NULL, 0 },
  { 152, NULL, 0 },
  { 153, NULL, 0 },
  { 154, NULL, 0 },
  { 155, NULL, 0 },
  { 156, NULL, 0 },
  { 157, NULL, 0 },
  { 158, NULL, 0 },
  { 159, NULL, 0 },
  { 160, NULL, 0 },
  { 161, NULL, 0 },
  { 162, NULL, 0 },
  { 163, NULL, 0 },
  { 164, NULL, 0 },
  { 165, NULL, 0 },
  { 166, NULL, 0 },
  { 167, NULL, 0 },
  { 168, NULL, 0 },
  { 169, NULL, 0 },
  { 170, NULL, 0 },
  { 171, NULL, 0 },
  { 172, NULL, 0 },
  { 173, NULL, 0 },
  { 174, NULL, 0 },
  { 175, NULL, 0 },
  { 176, NULL, 0 },
  { 177, NULL, 0 },
  { 178, NULL, 0 },
  { 179, NULL, 0 },
  { 180, NULL, 0 },
  { 181, NULL, 0 },
  { 182, NULL, 0 },
  { 183, NULL, 0 },
  { 184, NULL, 0 },
  { 185, NULL, 0 },
  { 186, NULL, 0 },
  { 187, NULL, 0 },
  { 188, NULL, 0 },
  { 189, NULL, 0 },
  { 190, NULL, 0 },
  { 191, NULL, 0 },
  { 192, NULL, 0 },
  { 193, NULL, 0 },
  { 194, NULL, 0 },
  { 195, NULL, 0 },
  { 196, NULL, 0 },
  { 197, NULL, 0 },
  { 198, NULL, 0 },
  { 199, NULL, 0 },
  { 200, NULL, 0 },
  { 201, NULL, 0 },
  { 202, NULL, 0 },
  { 203, NULL, 0 },
  { 204, NULL, 0 },
  { 205, NULL, 0 },
  { 206, NULL, 0 },
  { 207, NULL, 0 },
  { 208, NULL, 0 },
  { 209, NULL, 0 },
  { 210, NULL, 0 },
  { 211, NULL, 0 },
  { 212, NULL, 0 },
  { 213, NULL, 0 },
  { 214, NULL, 0 },
  { 215, NULL, 0 },
  { 216, NULL, 0 },
  { 217, NULL, 0 },
  { 218, NULL, 0 },
  { 219, NULL, 0 },
  { 220, NULL, 0 },
  { 221, NULL, 0 },
  { 222, NULL, 0 },
  { 223, NULL, 0 },
  { 224, NULL, 0 },
  { 225, NULL, 0 },
  { 226, NULL, 0 },
  { 227, NULL, 0 },
  { 228, NULL, 0 },
  { 229, NULL, 0 },
  { 230, NULL, 0 },
  { 231, NULL, 0 },
  { 232, NULL, 0 },
  { 233, NULL, 0 },
  { 234, NULL, 0 },
  { 235, NULL, 0 },
  { 236, NULL, 0 },
  { 237, NULL, 0 },
  { 238, NULL, 0 },
  { 239, NULL, 0 },
  { 240, NULL, 0 },
  { 241, NULL, 0 },
  { 242, NULL, 0 },
  { 243, NULL, 0 },
  { 244, NULL, 0 },
  { 245, NULL, 0 },
  { 246, NULL, 0 },
  { 247, NULL, 0 },
  { 248, NULL, 0 },
  { 249, NULL, 0 },
  { 250, NULL, 0 },
  { 251, NULL, 0 },
  { 252, NULL, 0 },
  { 253, NULL, 0 },
  { 254, NULL, 0 },
  { 255, NULL, 0 },
};

// Some stats on program execution, used to improve error reporting.
static size_t bytes_read;
static unsigned char this_command;
static size_t cmd_length;

// Reports an error and exits.
static void __attribute__((noreturn)) die(const char *msg) {
  perror(msg);
  fprintf(stderr, "  after %zu bytes read\n", bytes_read);
  fprintf(stderr, "  during command %d\n", this_command);
  fprintf(stderr, "  length %zu\n", cmd_length);
  exit(1);
}

// Checks a condition and exits if it fails.  A conditional version of 'die.'
static void require(bool condition, const char *msg) {
  if (!condition) die(msg);
}

// A version of read(2) that aborts on any error.
static size_t read_or_die(int fd, void *buf, size_t nbyte) {
  ssize_t n = read(fd, buf, nbyte);
  if (n < 0) {
    die("reading");
  }

  bytes_read += n;

  return (size_t) n;
}

// A version of write(2) that aborts on any error.
static size_t write_or_die(int fd, const void *buf, size_t nbyte) {
  ssize_t n = write(fd, buf, nbyte);
  if (n < 0) {
    die("writing");
  }

  return (size_t) n;
}

// The Maxim/iButton CRC algorithm prescribed by the RepRap folks.
static unsigned char compute_crc(const unsigned char *data, size_t length) {
  unsigned char crc = 0;
  for (size_t i = 0; i < length; i++) {
    crc ^= data[i];
    for (int j = 0; j < 8; j++) {
      if (crc & 1) {
        crc = (crc >> 1) ^ 0x8C;
      } else {
        crc = crc >> 1;
      }
    }
  }

  return crc;
}

// The start byte of encapsulated packets.
static const unsigned char kStartByte = 0xD5;
// A buffer for holding outgoing packets.
static unsigned char packet[32 /* maximum payload */ + 3 /* framing */];


int main(int argc, char *argv[]) {
  // Initialize the packet framing -- we'll never write this again.
  packet[0] = kStartByte;

  while (1) {
    // Read command byte into position at 2
    size_t n = read_or_die(0, packet + 2, 1);
    if (n == 0) break;

    unsigned char id = packet[2];
    this_command = id;
    require(commands[id].is_known_command(), "encountered unknown command");

    ssize_t length = commands[id].length;
    if (length == kToolActionLength) {
      // Read encapsulation header
      n = read_or_die(0, packet + 3, 3);
      require(n == 3, "truncated tool action command header");
      length = packet[5];
      cmd_length = length;
      n = read_or_die(0, packet + 6, length);
      length += 3;
    } else {
      cmd_length = length;
      require(length >= 0, "table contains unexpected negative length");
      require(length <= 32, "table contains bogus length");
      packet[1] = length + 1;
      n = read_or_die(0, packet + 3, length);
      require(n == length, "truncated packet body");
    }

    packet[3 + length] = compute_crc(packet + 3, length);

    n = write_or_die(1, packet, length + 4);
    if (n == 0) die("packet failed to write");
  }
}
