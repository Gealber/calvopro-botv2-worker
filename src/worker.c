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

/*download video or thumb*/
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
  /*Encoding*/
  curl_easy_setopt(hnd, CURLOPT_ACCEPT_ENCODING, "");
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
  const cJSON *imageurl = NULL;
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
  /*image url*/
  imageurl = cJSON_GetObjectItemCaseSensitive(json, "imageurl");
  if (cJSON_IsString(imageurl) && (imageurl->valuestring != NULL))
  {
    data->imageurl = strdup(imageurl->valuestring);
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

/*perform the download and upload of the video.
 * Return 1 on sucess and 0 on failure*/
int download_upload(DataIncome *data_income, char *file_id)
{
  char thumb_path[100] = {0};
  CURLcode ret;
  /*create the folder in case it doesn't exists*/
  create_folder(data_income->chatid);
  debug("Downloading video...");
  ret = download(data_income->url, data_income->path);
  if(CURLE_OK != ret) {
    log_err("Failed to download (%d) error", ret);
    return 0;
  }

  if(data_income->imageurl && strlen(data_income->imageurl) > 0) {
    debug("Downloading thumb...");
    snprintf(thumb_path, strlen(data_income->path) + 5, "%s.jpg", data_income->path);
    ret = download(data_income->imageurl, thumb_path);
    if(CURLE_OK != ret) {
      log_err("Failed to download thumb (%d) error", ret);
    }
  }

  /*it will be resized as need*/
  debug("Uploading video to Telegram API...");
  /*this is the part where we upload to Telegram*/
  ret = send_video(data_income->chatid, thumb_path, data_income->path, file_id);
  if(CURLE_OK != ret) {
    log_err("Failed to send video (%d)", ret);
  }
  /*this is the part where we upload to Telegram*/

  /*removing downloaded file, to save space we are poor*/
  int rc = remove(data_income->path);
  if(rc) {
    log_warn("Error removing file in path: %s", data_income->path);
    return 0;
  }
  return 1;
}

/* update_redis: put the file_id into redis and decrement
 * the download counter for the user who make the request.*/
int update_redis(redisContext *rctx, DataIncome *data_income, char *file_id)
{
  int ret = 1;
  redisReply *reply;
  if(strlen(file_id) == 0) {
    log_err("file_id is empty unable to store key");
    ret = 0;
  } else {
    /*add the file_id into redis, with an expiration of 1 month*/
    reply = redisCommand(rctx, "SET %s %s EX %u NX", data_income->hashkey, file_id, 2592000);
    freeReplyObject(reply);
  }
  /*decresing counter of dowload*/
  reply = redisCommand(rctx, "DECR %s", data_income->chatid);
  freeReplyObject(reply);
  return ret;
}

/* worker_routine: this routine is on a thread.
 * It waits for task on a PULL ZMQ socket.
 * Four(NUMT) instances of this "routine" are fired
 * at the start of the program.*/
void *worker_routine(void *context)
{
  int rc = 0;
  /*contains the data of a task*/
  DataIncome *data_income;
  /*store the file_id from Telegram response*/
  char *file_id = malloc(100);
  memset(file_id, 0, 100);

  /*redis context to store
   * hashkey: file_id*/
  redisContext *rctx = redisCtx();

  void *receiver = zmq_socket(context, ZMQ_PULL);
  rc = zmq_connect(receiver, "inproc://workers");
  if(rc != 0) {
    log_err("Unable to fire worker");
    free(rctx);
  }
  debug("[RECV]: worker socket is ready on: inproc://workers...");

  /*To notify when to kill a socket*/
  void *controller = zmq_socket(context, ZMQ_SUB);
  rc = zmq_connect(controller, "tcp://localhost:5559");
  assert( rc == 0 );
  /*subscribe to anything that comes*/
  zmq_setsockopt(controller, ZMQ_SUBSCRIBE, "", 0);
  debug("[CONTROL_SUB]: control socket is ready on: 5559...");

  /*need to process incomming messages from two sockets
   * receiver and controller. This is a way to do multiplexing
   * with ZMQ, or at least is how I understood.*/
  zmq_pollitem_t items[] = {
    {receiver, 0, ZMQ_POLLIN, 0},
    {controller, 0, ZMQ_POLLIN, 0}
  };

  while(1) {
    zmq_poll(items, 2, -1);
    /*if there's an event in PULL socket, a task*/
    if(items[0].revents & ZMQ_POLLIN) {
      /*a json string pull from redis and passed through
       * the PUSH socket in main. I think a sketch is needed
       * to understand the flow.*/
      char *json_string = s_recv(receiver);
      if(strlen(json_string) > 0) {
        /*need to parse json into a DataIncome stuct*/
        data_income = parse_json(json_string);
        /*validate data_income*/
        if(valid_data(data_income)) {
          /*donwload and upload*/
          if(!download_upload(data_income, file_id))
            goto clean;

          if(!update_redis(rctx, data_income, file_id))
            goto clean;
          /*zeroing memmory data in file_id
           * zeroing?? wtf is that?*/
          memset(file_id, 0, strlen(file_id));
        } else {
          log_err("Invalid data_income supplied");
        }
        clean:
        destroy(data_income);
      }
      free(json_string);
    }

    /*if there's an event in SUB socket, a KILL signal*/
    if(items[1].revents & ZMQ_POLLIN) {
      log_warn("\nKILL received from controler, cleaning and killing worker...\n");
      break;
    }
  }

  /*cleaning up*/
  if(file_id)
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
  char *redis_passwd;
  redisContext *ctx;
  char *redis_url;
  char *redis_domain;
  int port;

  /*reading redis url env*/
  redis_url = getenv("REDIS_URL");
  if(!redis_url) {
    log_err("Empty REDIS_URL, make sure you this env was setted");
    return NULL;
  }
  /*reading redis password env*/
  redis_passwd = getenv("REDIS_PASSWORD");
  if(strlen(redis_passwd) == 0) {
    log_err("Empty REDIS_PASSWORD, make sure this env was setted");
    return NULL;
  }
  /*reading redis domain env*/
  redis_domain = getenv("REDIS_DOMAIN");
  if(strlen(redis_domain) == 0) {
    log_err("Empty REDIS_DOMAIN, make sure this env was setted");
    return NULL;
  }
  /*reading redis port env*/
  char *port_str = getenv("REDIS_PORT");
  if(strlen(port_str) != 0)
    port = atoi(port_str);
  else
    port = 6379;

  /*creating redis context*/
  ctx = redisConnect(redis_domain, port);
  if(!ctx || ctx->err) {
    if(ctx) {
      log_err("%s", ctx->errstr);
      redisFree(ctx);
    }
    else
      log_err("Can't allocate redis context");
    return NULL;
  }

  /*Authenticating*/
  reply= redisCommand(ctx, "AUTH %s", redis_passwd);
  if (reply->type == REDIS_REPLY_ERROR) {
    log_err("Unable to authenticate: with password %s ERR: %s", redis_passwd, reply->str);
    freeReplyObject(reply);
    redisFree(ctx);
    return NULL;
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
  redisReply *reply = NULL;
  redisReply *del_reply = NULL;
  redisContext *ctx = NULL;
  /*necessary for ZMQ stuff*/
  void *context = NULL;
  void *workers = NULL;
  void *controller = NULL;

  /*Constant values*/
  const char *TASK_QUEUE = "tasks";
  /*Right now is not been used*/
  const char *BACKUP_TASK_QUEUE = "tasks_back";

  /*redis context, need to be destroyed*/
  ctx = redisCtx();
  if(!ctx)
    return 0;

  /*initialize libcurl*/
  curl_global_init(CURL_GLOBAL_ALL);

  /*init bot*/
  if(!init_bot()) {
    log_err("Unable to init_bot");
    goto end;
  }

  /* creating PUSH socket to dispatch task to workers
   * in threads. This other workers are PULL sockets.*/
  context = zmq_ctx_new();
  workers = zmq_socket(context, ZMQ_PUSH);
  int rc = zmq_bind(workers, "inproc://workers");
  if(rc != 0) {
    log_err("Unable to create PUSH socket...");
    zmq_close(workers);
    goto end;
  }

  /*in order to clean the workers on a SIGTERM signal*/
  controller = zmq_socket(context, ZMQ_PUB);
  rc = zmq_bind(controller, "tcp://*:5559");
  if(rc != 0) {
    log_err("Unable to create PUB socket...");
    goto end;
  }

  /*initializing threads to do all the hard work
   * like a man Brrrr. I'm scared*/
  for(i = 0; i < NUMT; i++) {
    pthread_create(&tid[i], NULL, worker_routine, context);
  }

  s_catch_signals();
  while(1) {
    /*retrieve element in redis queue*/
    reply = redisCommand(ctx, "BRPOPLPUSH %s %s %d", TASK_QUEUE, BACKUP_TASK_QUEUE, TIMEOUT);
    if(!reply->str) {
      freeReplyObject(reply);
      /*Catching Ctr+C commands*/
      if(s_interrupted) {
        log_warn("\nInterrupting and cleaning up...");
        s_send(controller, "KILL");
        break;
      }
      continue;
    }

    /*Dispatching work to ZeroMQ sockets(workers)*/
    s_send(workers, reply->str);

    /* deleting backup queue, the backup queue is not been used
     * but for now let's leave this alone.
     * Refer to: https://aws.amazon.com/es/redis/Redis_Streams_MQ*/
    del_reply = redisCommand(ctx, "DEL %s", BACKUP_TASK_QUEUE);
    freeReplyObject(del_reply);
    freeReplyObject(reply);
    /*Catching also the Ctr+C*/
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

end:
  /*closing ZMQ sockets*/
  if(controller)
    zmq_close(controller);
  if(workers)
    zmq_close(workers);
  if(context)
    zmq_ctx_destroy(context);
  /*disconnect and free redis context*/
  redisFree(ctx);
  curl_global_cleanup();
  return 0;
}
