#ifndef _BOT_H
#define _BOT_H

#include <curl/curl.h>

#ifndef TESTDEV
#define BASE_URL "https://api.telegram.org/bot"
#else
#define BASE_URL "http://localhost:4000"
#endif

#define URL_MAX 256
#define USER_AGENT "calvopro-bot/v2"

struct MemoryStruct {
  char *memory;
  size_t size;
};

int init_bot(void);
int form_url(char *method_name, 
                    char *url, size_t url_size);
CURLcode send_video(char *chatid, char *input_file, char *file_id);

size_t WriteMemoryCallback(void *contents, size_t size,
                                  size_t nmemb, void *userp);
#endif
