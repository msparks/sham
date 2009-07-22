/*
Copyright (c) 2009, Matt Sparks
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
* The name of the creator may not be used to endorse or promote products
  derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <openssl/sha.h>


char *dict[1000];
unsigned int dict_size = 0;
unsigned char challenge_hash[20];
char *set[32];
char cur_phrase[512];
unsigned int cur_phrase_len = 0;
char *cur_phrase_ascii;
unsigned int ascii_idx = 0;
unsigned int ascii_offset = 0;
time_t start_time;
SHA_CTX ctx;

char *ascii_chars = ("!#$%&'()*+,-./012345"  /* 20 */
                     "6789:;<=>?@ABCDEFGHI"  /* 40 */
                     "JKLMNOPQRSTUVWXYZ[]^"  /* 60 */
                     "_`abcdefghijklmnopqr"  /* 80 */
                     "stuvwxyz{|}~!#$%&'()"  /* 100 */
                     "*+,-./0123456789:;<="  /* 120 */
                     ">?@ABCDEFGHIJKLMNOPQ"  /* 140 */
                     "STUVWXYZ[]^_`abcdefg"  /* 160 */
                     "hijklmnopqrstuvwxyz{"  /* 180 */
                     "|}~!#$%&'()*+,-./012"  /* 200 */
                     "3456789:;<=>?@ABCDEF"  /* 220 */
                     "GHIJKLMNOPQRSTUVWXYZ"  /* 240 */
                     "[]^_`abcdefghijk");    /* 256 */


#define BYTE_0(x)  (x & 0xFF)


/**
 * Find the hamming distance between two 5-byte SHA-1 hashes
 */
inline unsigned int hamming_distance(unsigned int *sha1, unsigned int *sha2)
{
  unsigned int dist = 0;
  unsigned int i;
  unsigned long long val;

  /* use GCC builtin __builtin_popcount*() (population count) to quickly count
     the set bits */
  val = ((unsigned long long*)sha1)[0] ^ ((unsigned long long*)sha2)[0];
  dist += __builtin_popcountll(val);

  val = ((unsigned long long*)sha1)[1] ^ ((unsigned long long*)sha2)[1];
  dist += __builtin_popcountll(val);

  val = sha1[4] ^ sha2[4];
  dist += __builtin_popcount(val);

  return dist;
}


/**
 * Read dictionary in from standard input
 */
void read_dictionary(unsigned int max_words)
{
  char buf[64];
  int size;

  while (fgets(buf, sizeof(buf), stdin)) {
    size = strlen(buf);
    if (buf[size - 1] == '\n')
      buf[size - 1] = 0;

    dict[dict_size++] = strdup(buf);
    if (dict_size - 1 == max_words)
      break;
  }
}


/**
 * Pick a word set of a given size
 */
void pick_set(int set_size)
{
  int i;
  int idx;
  char *word;
  int word_len;
  int offset = 0;

  /* seed rng */
  struct timeval tv;
  gettimeofday(&tv, NULL);
  unsigned int seed_value = (((unsigned int)tv.tv_sec +
                              (unsigned int)tv.tv_usec) *
                             (unsigned int)getpid());
  seed_value %= RAND_MAX;
  srand(seed_value);

  /* initalize SHA context */
  SHA1_Init(&ctx);

  for (i = 0; i < set_size; ++i) {
    word = dict[rand() % dict_size];
    word_len = strlen(word);
    set[i] = word;

    strcpy(cur_phrase + offset, word);
    strcpy(cur_phrase + offset + word_len, " ");

    /* update the ctx with this word and space */
    SHA1_Update(&ctx, cur_phrase + offset, word_len + 1);

    offset += word_len + 1;
  }

  /* initialize the 5 ASCII chars at the end */
  strcpy(cur_phrase + offset, "!!!!!");
  cur_phrase_len = strlen(cur_phrase);
  cur_phrase_ascii = cur_phrase + cur_phrase_len - 5;
  ascii_idx = 0;
}


/**
 * Repeatedly choose sets until the phrase length is close to a SHA-1 chunk
 * boundary.
 */
void pick_minimal_set(int set_size, int max_distance)
{
  int retries = 0;

  while (1) {
    pick_set(set_size);

    /* minimize distance to chunk boundary */
    int len = cur_phrase_len - 5;
    while (len > 64)
      len -= 64;

    if (len > max_distance && retries < 10) {
      ++retries;
      pick_set(set_size);
    } else {
      break;
    }
  }
}


/**
 * Update the SHA context with the last five ASCII characters and finalize.
 */
inline void compute_sha(unsigned char *buf)
{
  /* make new context */
  SHA_CTX cur_ctx;
  memcpy(&cur_ctx, &ctx, sizeof(SHA_CTX));

  /* update for ASCII bit at the end */
  SHA1_Update(&cur_ctx, cur_phrase_ascii, 5);

  /* finalize */
  SHA1_Final(buf, &cur_ctx);
}


/**
 * Randomize the last five ASCII characters in a rolling fashion. One
 * character is randomized per next() call. Characters are chosen from the
 * ascii_chars array using the 8 LSBs of a call to rand().
 */
inline void next()
{
  int i;
  int r;

  ++ascii_idx;
  if (++ascii_offset == 5)
    ascii_offset = 0;

  cur_phrase_ascii[ascii_offset] = ascii_chars[BYTE_0(rand())];
}


/**
 * Format a time string.
 */
void calc_duration(unsigned int sec, char *buf)
{
  unsigned int hr;
  unsigned int min;

  sec -= (hr = sec / 3600) * 3600;
  sec -= (min = sec / 60) * 60;

  sprintf(buf, "%02dh%02dm%02ds", hr, min, sec);
}


/**
 * Print hashing status, including time, lowest distance found, and hashing
 * speed.
 */
void print_status(unsigned int id,
                  unsigned long long million_iterations,
                  unsigned int min_dist,
                  time_t min_dist_time)
{
  unsigned int sec = time(NULL) - start_time;
  if (sec == 0)
    return;
  unsigned int freq = (million_iterations * 1000000) / sec;

  char total_time[16];
  char min_time[16];

  calc_duration(sec, total_time);
  calc_duration(min_dist_time - start_time, min_time);

  printf("[%2d] %6lluM iterations :: dist %d in %s / %s (%4d KHz)\n",
         id, million_iterations, min_dist, min_time, total_time, freq / 1000);

  /* if we've been running too long, exit */
  if (sec > 60 * 30) {
    printf("[%2d] time limit expired\n", id);
    exit(0);
  }
}


/**
 * Report a new low distance by running the included Python script.
 *
 * The Python script could do anything, but currently just opens a TCP socket
 * and sends the message. execlp() and Python were used in the interest of time,
 * instead of using BSD sockets in C.
 */
void report(const char *msg)
{
  char cmd[1024];

  /* fork and run the Python program in the child */
  if (fork() == 0) {
    execlp("./shamclient.py", "./shamclient.py", msg, NULL);
    printf("error running shamclient.py\n");
    exit(1);
  }
}


/**
 * A worker.
 */
void worker(unsigned int id)
{
  unsigned char cur_hash[20];
  unsigned int min_dist = 160;
  time_t min_dist_time = time(NULL);
  unsigned int cur_dist;
  unsigned long long int million_iterations = 0;
  unsigned long long int sub_iterations = 0;
  start_time = time(NULL);

  /* pick an initial set */
  pick_minimal_set(12, 5);

  while (1) {
    ++sub_iterations;

    compute_sha(cur_hash);
    cur_dist = hamming_distance((unsigned int*)challenge_hash,
                                (unsigned int*)cur_hash);

    if (cur_dist < min_dist) {
      /* only report interesting distances */
      if (cur_dist < 40) {
        printf("[%llu] distance: %d\n",
               (1000000 * million_iterations + sub_iterations),
               cur_dist);
        printf("  %s (%d)\n", cur_phrase, ascii_idx);

        report(cur_phrase);
      }

      /* record new low distance */
      min_dist = cur_dist;
      min_dist_time = time(NULL);
    }

    if (sub_iterations == 1000000) {
      ++million_iterations;
      sub_iterations = 0;

      /* print status every 10M iterations */
      if (million_iterations % 10 == 0)
        print_status(id, million_iterations, min_dist, min_dist_time);

      /* pick a new set */
      pick_minimal_set(12, 5);
    } else {
      /* randomize ASCII bits at the end */
      next();
    }
  }
}


/**
 * Fork n times and start workers in new processes
 */
void start_workers(unsigned int n)
{
  int i;
  int pid;

  for (i = 0; i < n; ++i) {
    pid = fork();
    if (pid == 0)
      worker(i);
    else if (pid < 0)
      printf("failed to fork\n");
  }
}


int main(int argc, char **argv)
{
  if (argc != 3) {
    printf("usage: %s <workers> <phrase>\n", argv[0]);
    exit(1);
  }

  /* get SHA-1 of challenge phrase */
  SHA1((unsigned char *)argv[2], strlen(argv[2]), challenge_hash);

  /* read 1000 words */
  read_dictionary(1000);

  int num_workers = strtol(argv[1], NULL, 10);

  /* start workers */
  int i;
  while (1) {
    for (i = 0; i < num_workers; ++i)
      waitpid(-1, NULL, 0);
    printf("starting workers...\n");
    start_workers(num_workers);
  }
}
