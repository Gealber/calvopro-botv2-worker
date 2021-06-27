#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <sys/utsname.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <hiredis/hiredis.h>
#include <curl/curl.h>
#include "worker.h"
#include "zhelpers.h"
#include "dbg.h"
#include "bot.h"
#include "cJSON.h"

#define NUMT 4
#define TIMEOUT 10

static int s_interrupted = 0;
static void s_signal_handler(int signal_value)
{
  s_interrupted = 1;
}

static void s_catch_signals(void)
{
  struct sigaction action;
  action.sa_handler = s_signal_handler;
  action.sa_flags = 0;
  sigemptyset(&action.sa_mask);
  sigaction(SIGINT, &action, NULL);
  sigaction(SIGTERM, &action, NULL);
}

int valid_data(DataIncome *data_income)
{
  if(!data_income)
    return 0;
  if(strlen(data_income->chatid) == 0)
    return 0;
  if(strlen(data_income->url) < 10)
    return 0;
  if(strlen(data_income->path) == 0)
    return 0;
  if(strlen(data_income->hashkey) == 0)
    return 0;
  return 1;
}

static size_t write_video(void *buffer, size_t size,
                          size_t nmemb, FILE *stream)
{
  size_t written = fwrite(buffer, size, nmemb, stream);
  return written;
}

/*download video*/
CURLcode download(char *url, const char *video_name)
{
  CURL *hnd;
  CURLcode ret = CURLE_OK;
  FILE *stream;
  hnd = curl_easy_init();
  if(!hnd) {
    ret = CURLE_OUT_OF_MEMORY;
    goto end;
  }

  /*setting handler options*/
  /*buffer size for copying*/
  curl_easy_setopt(hnd, CURLOPT_BUFFERSIZE, 8192L);
  if(strlen(url) == 0) {
    ret = CURLE_URL_MALFORMAT;
    goto end;
  }
  /*URL*/
  curl_easy_setopt(hnd, CURLOPT_URL, url);
  /*Use only IPv4*/
  curl_easy_setopt(hnd, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
  /*User Agent*/
  curl_easy_setopt(hnd, CURLOPT_USERAGENT, USER_AGENTS[RAND(8)]);
  /*Location and redirection header*/
  curl_easy_setopt(hnd, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 5L);
  /*Callback when there's data to write*/
  curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_video);
  /*Connect timeout*/
  curl_easy_setopt(hnd, CURLOPT_CONNECTTIMEOUT, 10L);
  /* abort if slower than 10 bytes/sec during 30 seconds */
  curl_easy_setopt(hnd, CURLOPT_LOW_SPEED_LIMIT, 10L);
  curl_easy_setopt(hnd, CURLOPT_LOW_SPEED_TIME, 30L);

  /*TCP Keep alive*/
  curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
  /*Enabling TCP Fast Open*/
  curl_easy_setopt(hnd, CURLOPT_TCP_FASTOPEN, 1L);

  stream = fopen(video_name, "wb");
  if(stream) {
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stream);

    ret = curl_easy_perform(hnd);
    if(ret == CURLE_OPERATION_TIMEDOUT)
      log_err("Aborting timeout reached...");

    /*clean up*/
    fclose(stream);
  }

end:
  curl_easy_cleanup(hnd);
  hnd = NULL;
  return ret;
}

/*create the json string from the data*/
char *create_jsonstr(DataIncome *data)
{
  char *string = NULL;
  cJSON *url = NULL;
  cJSON *chatid = NULL;
  cJSON *hashkey = NULL;
  cJSON *path = NULL;

  /*create monitor object*/
  cJSON *monitor = cJSON_CreateObject();
  if(!monitor)
    goto end;

  if(data->url) {
    url = cJSON_CreateString(data->url);
    if(!url)
      goto end;
  }
  /*adding to monitor, transferring the ownership
   * of the pointer*/
  cJSON_AddItemToObject(monitor, "url", url);

  if(data->chatid) {
    chatid = cJSON_CreateString(data->chatid);
    if(!chatid)
      goto end;
  }
  /*adding to monitor, transferring the ownership
   * of the pointer*/
  cJSON_AddItemToObject(monitor, "chatid", chatid);

  if(data->path) {
    path = cJSON_CreateString(data->path);
    if(!path)
      goto end;
  }
  /*adding to monitor, transferring the ownership
   * of the pointer*/
  cJSON_AddItemToObject(monitor, "path", path);

  if(data->hashkey) {
    hashkey = cJSON_CreateString(data->hashkey);
    if(!hashkey)
      goto end;
  }
  /*adding to monitor, transferring the ownership
   * of the pointer*/
  cJSON_AddItemToObject(monitor, "hashkey", hashkey);

  string = cJSON_Print(monitor);
  if(!string)
    fprintf(stderr, "Failed to print monitor.\n");

  end:
  cJSON_Delete(monitor);
  return string;
}

/*parse the json string and put info
 * into DataIncome struct*/
DataIncome *parse_json(char *string)
{
  const cJSON *url = NULL;
  const cJSON *chatid = NULL;
  const cJSON *hashkey = NULL;
  const cJSON *path = NULL;

  if(strlen(string) == 0)
    return NULL;

  cJSON *json = cJSON_Parse(string);
  if(!json) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            fprintf(stderr, "Error before: %s\n", error_ptr);
            fprintf(stderr, "Error string: %s\n", string);
        }
        return NULL;
  }
  DataIncome *data = calloc(sizeof(DataIncome), 1);
  if(!data)
    goto end;

  url = cJSON_GetObjectItemCaseSensitive(json, "url");
  if (cJSON_IsString(url) && (url->valuestring != NULL))
  {
    data->url = strdup(url->valuestring);
  }
  chatid = cJSON_GetObjectItemCaseSensitive(json, "chatid");
  if (cJSON_IsString(chatid) && (chatid->valuestring != NULL))
  {
    data->chatid = strdup(chatid->valuestring);
  }
  path = cJSON_GetObjectItemCaseSensitive(json, "path");
  if (cJSON_IsString(path) && (path->valuestring != NULL))
  {
    data->path = strdup(path->valuestring);
  }
  hashkey = cJSON_GetObjectItemCaseSensitive(json, "hashkey");
  if (cJSON_IsString(hashkey) && (hashkey->valuestring != NULL))
  {
    data->hashkey = strdup(hashkey->valuestring);
  }
end:
    cJSON_Delete(json);
    return data;
}

void create_folder(char *chatid)
{
  struct stat st = {0};
  /*create a directory in case it doesn't exists
   * chatid it's its name*/
  if(stat(chatid, &st) == -1)
    mkdir(chatid, 0700);
}

void *worker_routine(void *context)
{
  CURLcode ret;
  int rc = 0;
  redisReply *reply;
  DataIncome *data_income;
  char *file_id = malloc(100);
  memset(file_id, 0, 100);

  /*redis context to store
   * hashkey: file_id*/
  redisContext *rctx = redisCtx();

  void *receiver = zmq_socket(context, ZMQ_PULL);
  rc = zmq_connect(receiver, "inproc://workers");
  assert( rc == 0 );
  debug("[RECV]: worker socket is ready on: inproc://workers...");

  /*To notify when to kill a socket*/
  void *controller = zmq_socket(context, ZMQ_SUB);
  rc = zmq_connect(controller, "tcp://localhost:5559");
  assert( rc == 0 );
  zmq_setsockopt(controller, ZMQ_SUBSCRIBE, "", 0);
  debug("[CONTROL_SUB]: control socket is ready on: 5559...");

  /*need to process incomming messages from two sockets
   * receiver and controller*/
  zmq_pollitem_t items[] = {
    {receiver, 0, ZMQ_POLLIN, 0},
    {controller, 0, ZMQ_POLLIN, 0}
  };

  while(1) {
    zmq_poll(items, 2, -1);
    if(items[0].revents & ZMQ_POLLIN) {
      char *json_string = s_recv(receiver);
      if(strlen(json_string) > 0) {
        data_income = parse_json(json_string);
        if(valid_data(data_income)) {
          create_folder(data_income->chatid);
          debug("Downloading video...");
          ret = download(data_income->url, data_income->path);
          if(CURLE_OK != ret) {
            log_err("Failed to download (%d) error", ret);
            goto clean;
          }

          /*it will be resized as need*/
          debug("Uploading video to Telegram API...");
          ret = send_video(data_income->chatid,
                          data_income->path, file_id);

          if(CURLE_OK != ret) {
            log_err("Failed to send video (%d)", ret);
            goto clean;
          }

          /*removing downloaded file*/
          int rc = remove(data_income->path);
          if(rc) {
            log_warn("Error removing file in path: %s", data_income->path);
            goto clean;
          }

          if(strlen(file_id) == 0) {
            log_err("file_id is empty unable to store key");
            goto clean;
          }
          reply = redisCommand(rctx, "SET %s %s EX %u NX", data_income->hashkey, file_id, 2592000);
          freeReplyObject(reply);
          /*decresing counter of dowload*/
          reply = redisCommand(rctx, "DECR %s", data_income->chatid);
          freeReplyObject(reply);
          memset(file_id, 0, strlen(file_id));
        } else {
          log_err("Invalid data_income supplied");
        }
        clean:
        destroy(data_income);
      }
      free(json_string);
    }
    if(items[1].revents & ZMQ_POLLIN) {
      log_warn("\nKILL received from controler, cleaning and killing worker...\n");
      break;
    }
  }

  /*cleaning up*/
  free(file_id);
  zmq_close(receiver);
  zmq_close(controller);
  redisFree(rctx);
  return NULL;
}

/*create a redis context authenticated to the database*/
redisContext *redisCtx()
{
  redisReply *reply;
  redisContext *ctx;
  char *redis_url;
  char *redis_domain;
  char *redis_passwd;
  int port;

  /*reading redis url env*/
  redis_url = getenv("REDIS_URL");
  if(!redis_url) {
    log_err("Empty REDIS_URL, make sure you this env was setted");
    return NULL;
  }
  redis_passwd = getenv("REDIS_PASSWORD");
  if(strlen(redis_passwd) == 0) {
    log_err("Empty REDIS_PASSWORD, make sure this env was setted");
    return NULL;
  }
  redis_domain = getenv("REDIS_DOMAIN");
  if(strlen(redis_domain) == 0) {
    log_err("Empty REDIS_DOMAIN, make sure this env was setted");
    return NULL;
  }
  char *port_str = getenv("REDIS_PORT");
  if(strlen(port_str) != 0)
    port = atoi(port_str);
  else
    port = 6379;

  ctx = redisConnect(redis_domain, port);
  if(!ctx || ctx->err) {
    if(ctx)
      log_err("%s", ctx->errstr);
    else
      log_err("Can't allocate redis context");
    redisFree(ctx);
    return NULL;
  }

  /*Authenticating*/
  reply= redisCommand(ctx, "AUTH %s", redis_passwd);
  if (reply->type == REDIS_REPLY_ERROR) {
    log_err("Unable to authenticate: with password %s ERR: %s", redis_passwd, reply->str);
    freeReplyObject(reply);
  }
  log_info("Connected to redis on: %s", redis_url);
  freeReplyObject(reply);

  return ctx;
}

int main(int argc, char *argv[])
{
  /*Setting seed for random*/
  SEED();
  int i;
  pthread_t tid[NUMT];
  redisReply *reply;
  redisReply *del_reply;
  redisContext *ctx;

  /*Constant values*/
  const char *TASK_QUEUE = "tasks";
  const char *BACKUP_TASK_QUEUE = "tasks_back";

  /*need to be destroyed*/
  ctx = redisCtx();

  /*initialize libcurl*/
  curl_global_init(CURL_GLOBAL_ALL);

  /*init bot*/
  if(init_bot()) {
    log_err("Unable to init_bot");
    goto end;
  }

  /*creating client PUSH socket*/
  void *context = zmq_ctx_new();
  void *workers = zmq_socket(context, ZMQ_PUSH);
  int rc = zmq_bind(workers, "inproc://workers");
  if(rc != 0) {
    log_err("Unable to create PUSH socket...");
    zmq_close(workers);
    goto end;
  }

  void *controller = zmq_socket(context, ZMQ_PUB);
  rc = zmq_bind(controller, "tcp://*:5559");
  if(rc != 0) {
    log_err("Unable to create PUB socket...");
    goto end;
  }

  /*initializing threads to do all the hard work
   * like a man brrrr. I'm scared*/
  for(i = 0; i < NUMT; i++) {
    pthread_create(&tid[i], NULL, worker_routine, context);
  }

  /*this is done synchronously, not a good idea but for now is ok*/
  s_catch_signals();
  while(1) {
    /*retrieve element in redis queue*/
    reply = redisCommand(ctx, "BRPOPLPUSH %s %s %d", TASK_QUEUE, BACKUP_TASK_QUEUE, TIMEOUT);
    if(!reply->str) {
      freeReplyObject(reply);
      if(s_interrupted) {
        log_warn("\nInterrupting and cleaning up...");
        s_send(controller, "KILL");
        break;
      }
      continue;
    }

    /*Dispatching work*/
    s_send(workers, strdup(reply->str));

    del_reply = redisCommand(ctx, "DEL %s", BACKUP_TASK_QUEUE);
    freeReplyObject(del_reply);
    freeReplyObject(reply);
    if(s_interrupted) {
      log_warn("\nInterrupting and cleaning up...");
      s_send(controller, "KILL");
      break;
    }
  }

  /*joining threads*/
  for(i = 0; i < NUMT; i++) {
    pthread_join(tid[i], NULL);
  }

  /*disconnect and free context*/
end:
  zmq_close(controller);
  zmq_close(workers);
  zmq_ctx_destroy(context);
  redisFree(ctx);
  curl_global_cleanup();
  return 0;
}
