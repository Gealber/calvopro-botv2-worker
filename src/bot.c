#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "dbg.h"
#include "bot.h"
#include "cJSON.h"

static char *TOKEN_API;

int form_url(char *method_name, char *url,
               size_t url_size)
{
  int nb = snprintf(url, url_size, "%s%s/%s", BASE_URL, TOKEN_API, method_name);
  if( nb < url_size-1 ) {
    log_err("Written bytes on url was too short");
    return 1;
  }
  return 0;
}

size_t WriteMemoryCallback(void *contents, size_t size,
                                  size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(!ptr) {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

/*need to be freed*/
char *extract_fileid(char *string)
{
  const cJSON *result = NULL;
  const cJSON *video = NULL;
  const cJSON *fileid = NULL;
  char *data = NULL;

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

  result = cJSON_GetObjectItemCaseSensitive(json, "result");
  if(cJSON_IsObject(result))
  {
    video = cJSON_GetObjectItemCaseSensitive(result, "video");
    if(cJSON_IsObject(video)) {
      fileid = cJSON_GetObjectItemCaseSensitive(video, "file_id");
      if(cJSON_IsString(fileid) && (fileid->valuestring != NULL)) {
        data = strdup(fileid->valuestring);
      }
    }
  }
  cJSON_Delete(json);
  return data;
}

/* curl: curl handler
 * input_file: path to file
 * */
CURLcode send_video(char *chatid, char *input_file, char *file_id)
{
  char url[URL_MAX];
  CURL *curl;
  CURLcode ret;

  struct MemoryStruct chunk;
  chunk.memory = malloc(1);
  chunk.size = 0;

  curl_mime *form = NULL;
  curl_mimepart *field = NULL;

  char *method_name = "sendVideo";
  size_t url_size = strlen(method_name) + strlen(TOKEN_API) + strlen(BASE_URL);
  /*'\0' + backslash character */
  url_size += 2;
  if(url_size > URL_MAX) {
    ret = CURLE_URL_MALFORMAT;
    log_err("URL supplied is too large");
    return ret;
  }

  /*form the url*/
  int code = form_url(method_name, url, url_size);
  if(code) {
    ret = CURLE_URL_MALFORMAT;
    return ret;
  }

  curl = curl_easy_init();
  if(!curl) {
    ret = CURLE_OUT_OF_MEMORY;
    log_err("Unable to init easy curl");
    return ret;
  }

  /*Create the form*/
  form = curl_mime_init(curl);
  /*filling the form*/
  /*chat_id*/
  field = curl_mime_addpart(form);
  curl_mime_name(field, "chat_id");
  curl_mime_data(field, chatid, CURL_ZERO_TERMINATED);
  /*thumb*/
  field = curl_mime_addpart(form);
  curl_mime_name(field, "thumb");
  const char *thumb = "https://cdn77-pic.xnxx-cdn.com/videos/thumbs169xnxxll/f1/eb/52/f1eb523a7728a6b8431ca3b35b498c9e/f1eb523a7728a6b8431ca3b35b498c9e.12.jpg";
  curl_mime_data(field, thumb, CURL_ZERO_TERMINATED);
  /*video*/
  field = curl_mime_addpart(form);
  curl_mime_name(field, "video");
  curl_mime_filedata(field, input_file);

  /*URL*/
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);

  /*MIME POST*/
  curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);

  /*in memory write*/
  /* send all data to this function  */
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  /* we pass our 'chunk' struct to the callback function */
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

  long http_code = 0;
  ret = curl_easy_perform(curl);
  curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);
  if(ret != CURLE_OK) {
    log_err("Request didn't goes well");
    goto end;
  }
  /*checking return code*/
  if(http_code == 200) {
    /*storing in redis hashkey: fileid, 30 days*/
    char *ext_fileid = extract_fileid(chunk.memory);
    size_t ext_len = strlen(ext_fileid);
    if(ext_len > 100) {
      debug("file id > 100 characters");
      goto end;
    }
    memcpy(file_id, ext_fileid, ext_len);
    file_id[ext_len] = '\0';
    free(ext_fileid);
  } else {
    log_err("Expected 200 got (%lu) HTTP code", http_code);
  }

end:
  curl_mime_free(form);
  curl_easy_cleanup(curl);
  free(chunk.memory);
  curl = NULL;
  return ret;
}

int init_bot(void)
{
  TOKEN_API = getenv("TOKEN_TELGRAM_API");
  if(!TOKEN_API) {
    log_err("TOKEN_TELEGRAM_API environment variable is not setted");
    return 0;
  }
  return 1;
}
