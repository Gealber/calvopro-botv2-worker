#ifndef WORKER_H
#define WORKER_H

#include <time.h>
#include <stdlib.h>

char *USER_AGENTS[8] = {
 "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36",
 "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
 "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
 "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
 "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9",
 "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
 "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
 "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36"
};

#define SEED() srand(time(NULL))
#define RAND(i) rand() % i

#define FILEID_MAX 200

struct Video {
  const char *name;
  FILE *stream;
};

typedef struct DataIncome {
  char *url;
  char *chatid;
  char *path; /*path to file*/
  char *hashkey;
} DataIncome;

typedef struct TaskThread {
  DataIncome *data_income;
  void *sender;
} TaskThread;

void destroy(DataIncome *data)
{
  if(!data)
    return ;
  if(data->url)
    free(data->url);
  if(data->chatid)
    free(data->chatid);
  if(data->path)
    free(data->path);
  if(data->hashkey)
    free(data->hashkey);
  if(data)
    free(data);
}

static void s_signal_handler(int signal_value);
static void s_catch_signals(void);
static size_t write_video(void *buffer, size_t size,
                          size_t nmemb, FILE *stream);
CURLcode download(char *url, const char *video_name);
char *create_jsonstr(DataIncome *data);
DataIncome *parse_json(char *string);
void create_folder(char *chatid);
void print_sys(void);
void *worker_routine(void *context);

redisContext *redisCtx();

#endif /* WORKER_H */
