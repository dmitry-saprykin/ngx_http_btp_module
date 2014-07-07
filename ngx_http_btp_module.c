/*
 * based on ngx_http_pinba_module by Antony Dovgal, 
 */

/*
 
 
 В конфигурации nginx модуль включается так
 
 http {
    btp_enable on;
    btp_server 127.0.0.1:40000,127.0.0.1:40001,127.0.0.1:40002;
 
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_hash.h>

extern ngx_module_t ngx_http_fastcgi_module;

typedef struct {
    ngx_http_upstream_conf_t       upstream;

    ngx_str_t                      index;

    ngx_array_t                   *flushes;
    ngx_array_t                   *params_len;
    ngx_array_t                   *params;
    ngx_array_t                   *params_source;
    ngx_array_t                   *catch_stderr;

    ngx_array_t                   *fastcgi_lengths;
    ngx_array_t                   *fastcgi_values;

    ngx_hash_t                     headers_hash;
    ngx_uint_t                     header_params;

    ngx_flag_t                     keep_conn;

#if (NGX_HTTP_CACHE)
    ngx_http_complex_value_t       cache_key;
#endif

#if (NGX_PCRE)
    ngx_regex_t                   *split_regex;
    ngx_str_t                      split_name;
#endif
} ngx_http_btp_fastcgi_loc_conf_t;

#define BTP_STR_BUFFER_SIZE 257
#define BTP_ARRAY_KEY_BUFFER_SIZE 400 // 257 + ~150
#if (NGX_DEBUG)
  #define BTP_REQUEST_BUFFER_SIZE 2
#else
  #define BTP_REQUEST_BUFFER_SIZE 50
#endif

#define BTP_GET_SEGMENT_BY_VALUE(segment, group, value) \
do { \
    if( (value) < 1000 ) { \
      segment = & group ## _0_1k; \
    } \
    else if( (value) < 10000 ) { \
      segment = & group ## _1k_10k; \
    } \
    else { \
      segment = & group ## _10k_more; \
    } \
} while(0) \

typedef struct
{
  char key[BTP_ARRAY_KEY_BUFFER_SIZE];
  ngx_uint_t timers[BTP_REQUEST_BUFFER_SIZE];
  size_t timers_used;
}
ngx_btp2_request_item;

#define BTP_FLAG_GZIP 1
#define BTP_FLAG_CLIENT_SEND 2
#define BTP_FLAG_UPSTREAM_SEND 4
#define BTP_FLAG_UPSTREAM_RECEIVE 8
#define BTP_FLAG_CLIENT_RECEIVE 16
#define BTP_FLAG_CLIENT_RECEIVE_STATIC 32

typedef struct
{
  ngx_uint_t status;
  char script_name[BTP_STR_BUFFER_SIZE];
  uint64_t request_total;

  uint64_t client_send;
  uint64_t client_send_header;
  uint64_t upstream_send;
  uint64_t upstream_receive;
  uint64_t client_receive;
  uint64_t client_receive_static;
  uint64_t upstream_total;

  uint64_t request_size;
  uint64_t response_size;
  uint64_t response_gzip_size;

  char flags;
}
ngx_btp_request;

typedef struct
{
	ngx_flag_t enable;
	ngx_array_t *ignore_codes;
	ngx_url_t server;
	ngx_int_t skip_slashes;
	char *buffer;
	size_t buffer_size;
	size_t buffer_used_len;
	ngx_btp_request request_buffer[BTP_STR_BUFFER_SIZE];
	size_t request_buffer_used;
	struct
	{
    int fd;
    struct sockaddr_storage sockaddr;
    int sockaddr_len;
	}
	socket;
	char hostname[BTP_STR_BUFFER_SIZE];
  char groupname[BTP_STR_BUFFER_SIZE];
  char internalname[BTP_STR_BUFFER_SIZE];
  char contentname[BTP_STR_BUFFER_SIZE];
}
ngx_http_btp_loc_conf_t;

typedef struct
{
  time_t cliend_send_header_finish_sec;
  ngx_msec_t cliend_send_header_finish_msec;
}
ngx_http_btp_custom_ctx_t;

ngx_str_t btp_fastcgi_scriptname_param = ngx_string("PATH_TRANSLATED");

static void *ngx_http_btp_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_btp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_btp_init(ngx_conf_t *cf);
static char *ngx_http_btp_ignore_codes(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_btp_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void ngx_http_btp_get_scriptname(ngx_uint_t status, ngx_http_request_t *r, char *result, ngx_int_t skip_slashes);

static ngx_command_t  ngx_http_btp_commands[] = {
  {
    ngx_string("btp_enable"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },
  {
    ngx_string("btp_ignore_codes"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
    ngx_http_btp_ignore_codes,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },
  {
    ngx_string("btp_server"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
    ngx_http_btp_server,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },
  {
    ngx_string("btp_script_skip_slashes"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_btp_loc_conf_t, skip_slashes),
    NULL
  },

  ngx_null_command
};

static ngx_http_module_t  ngx_http_btp_module_ctx = {
  NULL,                   // preconfiguration
  ngx_http_btp_init,      // postconfiguration

  NULL,                           // create main configuration
  NULL,                           // init main configuration

  NULL,                           // create server configuration
  NULL,                           // merge server configuration

  ngx_http_btp_create_loc_conf,   // create location configration
  ngx_http_btp_merge_loc_conf     // merge location configration
};

ngx_module_t  ngx_http_btp_module = {
  NGX_MODULE_V1,
  &ngx_http_btp_module_ctx,   // module context
  ngx_http_btp_commands,      // module directives
  NGX_HTTP_MODULE,            // module type
  NULL,                       // init master
  NULL,                       // init module
  NULL,                       // init process
  NULL,                       // init thread
  NULL,                       // exit thread
  NULL,                       // exit process
  NULL,                       // exit master
  NGX_MODULE_V1_PADDING
};

static char *ngx_http_btp_ignore_codes(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_btp_loc_conf_t *lcf = conf;
	ngx_str_t *value;
	ngx_uint_t i, *pcode;
	ngx_int_t code;

	value = cf->args->elts;

	if (cf->args->nelts == 1 && ngx_strcmp(&value[1], "none") == 0)
	{
		lcf->ignore_codes = NULL;
		return NGX_OK;
	}

	if (lcf->ignore_codes == NULL)
	{
		lcf->ignore_codes = ngx_array_create(cf->pool, 4, sizeof(ngx_uint_t));
		if (lcf->ignore_codes == NULL)
		{
			return NGX_CONF_ERROR;
		}
	}

	for (i = 1; i < cf->args->nelts; i++)
	{
		char *dash  = ngx_strchr(value[i].data, '-');
		if (dash)
		{
			// a range of values
			u_char *data_copy, *dash_copy;
			int code1_len, code2_len, n;
			ngx_int_t code1, code2;

			code1_len = (dash - (char *)value[i].data);
			code2_len = value[i].len - code1_len;

			if (code1_len < 3 || code2_len < 3)
			{
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid status code value \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			data_copy = ngx_pstrdup(cf->pool, &value[i]);
			dash_copy = data_copy + code1_len;
			*dash_copy = '\0';
			
			code1 = ngx_atoi(data_copy, code1_len);
			if (code1 < 100 || code1 > 599)
			{
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid status code value \"%V\", values must not be less than 100 or greater than 599", &value[i]);
				return NGX_CONF_ERROR;
			}
			
			code2 = ngx_atoi(dash_copy + 1, code2_len - 1);
			if (code2 < 100 || code2 > 599)
			{
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid status code value \"%V\", values must not be less than 100 or greater than 599", &value[i]);
				return NGX_CONF_ERROR;
			}

			if (code1 >= code2)
			{
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid status code value \"%V\", range end must be greater than range start", &value[i]);
				return NGX_CONF_ERROR;
			}

			for (n = code1; n <= code2; n++)
			{
				pcode = ngx_array_push(lcf->ignore_codes);
				if (pcode == NULL)
				{
					return NGX_CONF_ERROR;
				}
				*pcode = (ngx_uint_t)n;
			}


		}
		else
		{
			// just a simple value
			code = ngx_atoi(value[i].data, value[i].len);
			if (code < 100 || code > 599)
			{
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid status code value \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			pcode = ngx_array_push(lcf->ignore_codes);
			if (pcode == NULL)
			{
				return NGX_CONF_ERROR;
			}

			*pcode = (ngx_uint_t)code;
		}
	}

	return NGX_CONF_OK;
}

static char *ngx_http_btp_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_str_t *value;
	ngx_url_t u;
	ngx_http_btp_loc_conf_t *lcf = conf;
	struct addrinfo *ai_list, *ai_ptr, ai_hints;
	int fd, status;
	ngx_uint_t selected, count = 1;

	value = cf->args->elts;
  value = &value[1];

  char *str_to_scan = (char *)value->data;
  while( str_to_scan )
  {
    str_to_scan = ngx_strstr(str_to_scan, ",");
    if( str_to_scan )
    {
      count++;
      str_to_scan++;
    }
  }

  ngx_memzero(&u, sizeof(ngx_url_t));
  if( count < 2 )
  {
    u.url = value[0];
  }
  else
  {
    selected = (random() % count);
    str_to_scan = (char *)value->data;
    while( selected )
    {
      str_to_scan = ngx_strstr(str_to_scan, ",");
      str_to_scan++;
      selected--;
    }

    uint server_len;
    char *server_data;
    if( ngx_strstr(str_to_scan, ",") )
    {
      server_len = ngx_strstr(str_to_scan, ",") - str_to_scan;
    }
    else
    {
      server_len = ngx_strlen(str_to_scan);
    }
    server_data = ngx_palloc(cf->pool, server_len);
    if( !server_data )
    {
      return NGX_CONF_ERROR;
    }
    strncpy(server_data, str_to_scan, server_len);
    u.url.data = (u_char *)server_data;
    u.url.len = server_len;
  }

	u.no_resolve = 0;

	if (ngx_parse_url(cf->pool, &u) != NGX_OK)
	{
		if (u.err)
		{
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "%s in btp server \"%V\"", u.err, &u.url);
		}
		return NGX_CONF_ERROR;
	}

	if (u.no_port)
	{
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "no port in btp server \"%V\"", &u.url);
		return NGX_CONF_ERROR;
	}

	lcf->socket.fd = -1;
	lcf->server = u;

	ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "btp module: selected server \"%V\"", &u.url);

	memset(&ai_hints, 0, sizeof(ai_hints));
	ai_hints.ai_flags = 0;
#ifdef AI_ADDRCONFIG
	ai_hints.ai_flags |= AI_ADDRCONFIG;
#endif
	ai_hints.ai_family = AF_UNSPEC;
	ai_hints.ai_socktype  = SOCK_DGRAM;
	ai_hints.ai_addr = NULL;
	ai_hints.ai_canonname = NULL;
	ai_hints.ai_next = NULL;

	ai_list = NULL;

	char *addrinfo_host = ngx_palloc(cf->pool, lcf->server.host.len + 1);
	strncpy(addrinfo_host, (char *)lcf->server.host.data, lcf->server.host.len);
	addrinfo_host[lcf->server.host.len] = '\0';

	char *addrinfo_port = ngx_palloc(cf->pool, lcf->server.port_text.len + 1);
  strncpy(addrinfo_port, (char *)lcf->server.port_text.data, lcf->server.port_text.len);
  addrinfo_port[lcf->server.port_text.len] = '\0';

  ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "btp module: host - \"%s\" port - %s", addrinfo_host, addrinfo_port);

	status = getaddrinfo(addrinfo_host, addrinfo_port, &ai_hints, &ai_list);
	ngx_pfree(cf->pool, addrinfo_port);
	ngx_pfree(cf->pool, addrinfo_host);
	if (status != 0)
	{
		ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "btp module: getaddrinfo(\"%V\") failed: %s", &lcf->server.url, gai_strerror(status));
		return NGX_CONF_ERROR;
	}

	fd = -1;
	for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next)
	{
		fd = socket(ai_ptr->ai_family, ai_ptr->ai_socktype, ai_ptr->ai_protocol);
		if (fd >= 0)
		{
			lcf->socket.fd = fd;
			memcpy(&lcf->socket.sockaddr, ai_ptr->ai_addr, ai_ptr->ai_addrlen);
			lcf->socket.sockaddr_len = ai_ptr->ai_addrlen;
			break;
		}
	}

	freeaddrinfo(ai_list);
	if (fd < 0)
	{
		ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "btp module: socket() failed: %s", strerror(errno));
		return NGX_CONF_ERROR;
	}
	return NGX_CONF_OK;
}

static char* ngx_http_btp_itoa(uint64_t val)
{
	static char buf[32] = {0};	
	int i = 30;
  if(val == 0)
  {
    buf[i] = '0';
    --i;
  }
	else
	{
    for(; val && i ; --i, val /= 10)
    {
      buf[i] = "0123456789"[val % 10];
    }
  }
	return &buf[i+1];	
}

//---------------------------------------------------------------------
/*
{
  "jsonrpc":"2.0",
  "method":"publish",
  "params":{
    "channel":"btp2.rt",
    "content":[
       { "name":"service~~service1~~server1~~op1", "cl":[1,1,1]},
       { "name":"service~~service1~~server1~~op2", "cl":[2,2,2]},
       { "name":"service~~service2~~server1~~op1", "cl":[3,3,3]},
       { "name":"service~~service2~~server1~~op2", "cl":[4,4,4]},
       { "name":"service~~service1~~op1", "cl":[1,1,1]},
       { "name":"service~~service1~~op2", "cl":[2,2,2]},
       { "name":"service~~service2~~op1", "cl":[3,3,3]},
       { "name":"service~~service2~~op2", "cl":[4,4,4]},
       { "name":"script~~script1.phtml~~service1~~op1", "cl":[1,1,1]},
       { "name":"script~~script1.phtml~~service1~~op2", "cl":[2,2,2]},
       { "name":"script~~script1.phtml~~service2~~op1", "cl":[3,3,3]},
       { "name":"script~~script1.phtml~~service2~~op2", "cl":[4,4,4]}
    ]
  }
}
 */

ngx_str_t btp_key_service = ngx_string("service~~"),
  btp_key_script = ngx_string("script~~"),
  btp_key_separator = ngx_string("~~"),
  btp_key_opener = ngx_string("{\"jsonrpc\":\"2.0\",\"method\":\"publish\",\"params\":{\"channel\":\"btp2.rt\",\"content\":["),
  btp_key_closer = ngx_string("]}}\r\n"),
  btp_key_item_open = ngx_string("{\"name\":\""),
  btp_key_item_cl = ngx_string("\",\"cl\":["),
  btp_key_item_close = ngx_string("]}"),
  btp_key_comma = ngx_string(","),

  btp_key_response_gzip_size = ngx_string("response_gzip_size"),
  btp_key_response_gzip_size_0_1k = ngx_string("response_gzip_size_0_1k"),
  btp_key_response_gzip_size_1k_10k = ngx_string("response_gzip_size_1k_10k"),
  btp_key_response_gzip_size_10k_more = ngx_string("response_gzip_size_10k_more"),

  btp_key_response_size = ngx_string("response_size"),
  btp_key_response_size_0_1k = ngx_string("response_size_0_1k"),
  btp_key_response_size_1k_10k = ngx_string("response_size_1k_10k"),
  btp_key_response_size_10k_more = ngx_string("response_size_10k_more"),

  btp_key_request_size = ngx_string("request_size"),
  btp_key_request_size_0_1k = ngx_string("request_size_0_1k"),
  btp_key_request_size_1k_10k = ngx_string("request_size_1k_10k"),
  btp_key_request_size_10k_more = ngx_string("request_size_10k_more"),

  btp_key_client_send = ngx_string("client_send"),
  btp_key_client_send_header = ngx_string("client_send_header"),
  btp_key_upstream_send = ngx_string("upstream_send"),
  btp_key_upstream_receive = ngx_string("upstream_receive"),
  btp_key_upstream_total = ngx_string("upstream_total"),
  btp_key_client_receive = ngx_string("client_receive"),
  btp_key_client_receive_static = ngx_string("client_receive_static"),
  btp_key_total = ngx_string("total")
  ;

static int ngx_http_btp_insert_ts( ngx_array_t *arr, char *key,  uint64_t ts)
{
  size_t j;
  ngx_btp2_request_item *item, *found = NULL;
  for(j = 0; j < arr->nelts; j++)
  {
    item = arr->elts;
    item = &item[j];
    if( !ngx_strcmp(key, item->key) )
    {
      found = item;
      break;
    }
  }

  if(found == NULL)
  {
    ngx_btp2_request_item* new = ngx_array_push(arr);
    if(new == NULL)
    {
      return -1;
    }
    memset(new->key, '\0', sizeof(new->key));
    memcpy(new->key, key, ngx_strlen(key));
    new->timers_used = 1;
    new->timers[0] = ts;
  }
  else
  {
    found->timers[found->timers_used] = ts;
    found->timers_used += 1;
  }

  return 0;
}

static int ngx_http_btp_prepare_counter(
    const ngx_btp_request *request,
    ngx_http_request_t *r,
    ngx_array_t *result,
    ngx_str_t *suffix,
    uint64_t value,
    size_t key_base_len,
    char *key
)
{
  size_t key2_len;
  char *dest, *key2;

  key2_len = key_base_len + suffix->len;
  key2 = ngx_pcalloc(r->pool, key2_len + 1);

  memcpy(key2, key, key_base_len);
  dest = key2 + key_base_len;

  memcpy(dest, suffix->data, suffix->len);
  key2[key2_len] = '\0';

  if( ngx_http_btp_insert_ts(result, key2, value) )
  {
    ngx_pfree(r->pool, key2);
    return -1;
  }
  ngx_pfree(r->pool, key2);
  return 0;
}

static int ngx_http_btp_prepare_upstream_counters(
    const ngx_btp_request *request,
    ngx_http_request_t *r,
    ngx_array_t *result,
    size_t key_base_len,
    char *key
)
{
  //BTP_FLAG_CLIENT_SEND
  if( request->flags & BTP_FLAG_CLIENT_SEND )
  {
    if( ngx_http_btp_prepare_counter(
        request, r, result,
        &btp_key_client_send, request->client_send,
        key_base_len, key
    ))
    {
      return -1;
    }

  }

  //BTP_FLAG_UPSTREAM_SEND
  if( request->flags & BTP_FLAG_UPSTREAM_SEND )
  {
    if( ngx_http_btp_prepare_counter(
        request, r, result,
        &btp_key_upstream_send, request->upstream_send,
        key_base_len, key
    ))
    {
      return -1;
    }
  }

  //BTP_FLAG_UPSTREAM_RECEIVE
  if( request->flags & BTP_FLAG_UPSTREAM_RECEIVE )
  {
    if( ngx_http_btp_prepare_counter(
        request, r, result,
        &btp_key_upstream_receive, request->upstream_receive,
        key_base_len, key
    ))
    {
      return -1;
    }
  }

  //BTP_FLAG_CLIENT_RECEIVE
  if( request->flags & BTP_FLAG_CLIENT_RECEIVE )
  {
    if( ngx_http_btp_prepare_counter(
        request, r, result,
        &btp_key_client_receive, request->client_receive,
        key_base_len, key
    ))
    {
      return -1;
    }
  }

  //BTP_FLAG_CLIENT_RECEIVE_STATIC
  if( request->flags & BTP_FLAG_CLIENT_RECEIVE_STATIC )
  {
    if( ngx_http_btp_prepare_counter(
        request, r, result,
        &btp_key_client_receive_static, request->client_receive_static,
        key_base_len, key
    ))
    {
      return -1;
    }
  }

  //UPSTREAM TOTAL
  if( ngx_http_btp_prepare_counter(
      request, r, result,
      &btp_key_upstream_total, request->upstream_total,
      key_base_len, key
  ))
  {
    return -1;
  }

  //TOTAL
  if( ngx_http_btp_prepare_counter(
      request, r, result,
      &btp_key_total, request->request_total,
      key_base_len, key
  ))
  {
    return -1;
  }

  //CLIENT SEND_HEADER
  if( ngx_http_btp_prepare_counter(
      request, r, result,
      &btp_key_client_send_header, request->client_send_header,
      key_base_len, key
  ))
  {
    return -1;
  }

  return 0;
}

static int ngx_http_btp_prepare_content_counters(
    const ngx_btp_request *request,
    ngx_http_request_t *r,
    ngx_array_t *result,
    size_t key_base_len,
    char *key
)
{
  ngx_str_t *segment;
  uint64_t value;

  if( request->response_gzip_size )
  {
    value = request->response_gzip_size;
    if( ngx_http_btp_prepare_counter(
        request, r, result,
        &btp_key_response_gzip_size, value,
        key_base_len, key
    ))
    {
      return -1;
    }

    BTP_GET_SEGMENT_BY_VALUE(segment, btp_key_response_gzip_size, value);
    if( ngx_http_btp_prepare_counter( request, r, result, segment, value, key_base_len, key ))
    {
      return -1;
    }
  }
  //----------------response_size-------------------------------
  value = request->response_size;
  if( ngx_http_btp_prepare_counter(
      request, r, result,
      &btp_key_response_size, value,
      key_base_len, key
  ))
  {
    return -1;
  }

  BTP_GET_SEGMENT_BY_VALUE(segment, btp_key_response_size, value);
  if( ngx_http_btp_prepare_counter( request, r, result, segment, value, key_base_len, key ))
  {
    return -1;
  }
  //----------------request_size-------------------------------
  value = request->request_size;
  if( ngx_http_btp_prepare_counter(
      request, r, result,
      &btp_key_request_size, value,
      key_base_len, key
  ))
  {
    return -1;
  }

  BTP_GET_SEGMENT_BY_VALUE(segment, btp_key_request_size, value);
  if( ngx_http_btp_prepare_counter( request, r, result, segment, value, key_base_len, key ))
  {
    return -1;
  }

  return 0;
}

static char * make_service_server_op(
    ngx_http_request_t *r,
    const char *service,
    const char *server,
    int suffix_len,
    size_t *total_len)
{
  char *dest, *output;

  *total_len = btp_key_service.len + ngx_strlen(service) + ngx_strlen(server) + 2 * btp_key_separator.len + suffix_len;
  output = ngx_pcalloc(r->pool, *total_len + 1);
  dest = output;

  //"service~~"
  memcpy(dest, btp_key_service.data, btp_key_service.len);
  dest += btp_key_service.len;

  //service1
  memcpy(dest, service, ngx_strlen(service));
  dest += ngx_strlen(service);

  //~~
  memcpy(dest, btp_key_separator.data, btp_key_separator.len);
  dest += btp_key_separator.len;

  //server1
  memcpy(dest, server, ngx_strlen(server));
  dest += ngx_strlen(server);

  //~~
  memcpy(dest, btp_key_separator.data, btp_key_separator.len);
  dest += btp_key_separator.len;

  output[*total_len] = '\0';

  return output;
}

static char * make_service_op(
    ngx_http_request_t *r,
    const char *service,
    int suffix_len,
    size_t *total_len)
{
  char *dest, *output;

  *total_len = btp_key_service.len + ngx_strlen(service) + btp_key_separator.len + suffix_len;
  output = ngx_pcalloc(r->pool, *total_len + 1);
  dest = output;

  //"service~~"
  memcpy(dest, btp_key_service.data, btp_key_service.len);
  dest += btp_key_service.len;

  //service1
  memcpy(dest, service, ngx_strlen(service));
  dest += ngx_strlen(service);

  //~~
  memcpy(dest, btp_key_separator.data, btp_key_separator.len);
  dest += btp_key_separator.len;

  output[*total_len] = '\0';

  return output;
}

static char * make_script_service_op(
    ngx_http_request_t *r,
    const char *script,
    const char *service,
    int suffix_len,
    size_t *total_len)
{
  char *dest, *output;

  *total_len = btp_key_script.len + ngx_strlen(script) + ngx_strlen(service) + 2 * btp_key_separator.len + suffix_len;
  output = ngx_pcalloc(r->pool, *total_len + 1);
  dest = output;

  //"script~~"
  memcpy(dest, btp_key_script.data, btp_key_script.len);
  dest += btp_key_script.len;

  //script_name.phtml
  memcpy(dest, script, ngx_strlen(script));
  dest += ngx_strlen(script);

  //~~
  memcpy(dest, btp_key_separator.data, btp_key_separator.len);
  dest += btp_key_separator.len;

  //service1
  memcpy(dest, service, ngx_strlen(service));
  dest += ngx_strlen(service);

  //~~
  memcpy(dest, btp_key_separator.data, btp_key_separator.len);

  output[*total_len] = '\0';

  return output;
}

static ngx_array_t* ngx_http_btp_prepare_btp2_request(const ngx_http_btp_loc_conf_t *lcf, ngx_http_request_t *r)
{
  size_t i, key_len;
  ngx_array_t *result = ngx_array_create(r->pool, 3 * BTP_REQUEST_BUFFER_SIZE, sizeof(ngx_btp2_request_item));
  char *key, *dest, *operation;

  for(i = 0; i < lcf->request_buffer_used; i++)
  {
      const ngx_btp_request *request = &lcf->request_buffer[i];
      operation = ngx_http_btp_itoa(request->status);

      //------------------- service~~service1~~server1~~op1 --------------------------------
      {
        key = make_service_server_op(r, lcf->groupname, lcf->hostname, ngx_strlen(operation), &key_len);
        dest = key + key_len - ngx_strlen(operation);
        memcpy(dest, operation, ngx_strlen(operation));
        if( ngx_http_btp_insert_ts(result, key, request->request_total) )
        {
          ngx_array_destroy(result);
          ngx_pfree(r->pool, key);
          return NULL;
        }
        ngx_pfree(r->pool, key);
        //------------------------internal prefix------------
        key = make_service_server_op(r, lcf->internalname, lcf->hostname, 0, &key_len);
        if( ngx_http_btp_prepare_upstream_counters(request, r, result, key_len, key) )
        {
          ngx_array_destroy(result);
          ngx_pfree(r->pool, key);
          return NULL;
        }
        ngx_pfree(r->pool, key);
        //------------------------content prefix------------
        key = make_service_server_op(r, lcf->contentname, lcf->hostname, 0, &key_len);
        if( ngx_http_btp_prepare_content_counters(request, r, result, key_len, key) )
        {
          ngx_array_destroy(result);
          ngx_pfree(r->pool, key);
          return NULL;
        }
        ngx_pfree(r->pool, key);
      }
      //------------------- end --------------------------------

      //------------------- service~~service1~~op1 --------------------------------
      {
        key = make_service_op(r, lcf->groupname, ngx_strlen(operation), &key_len);
        dest = key + key_len - ngx_strlen(operation);
        memcpy(dest, operation, ngx_strlen(operation));
        if( ngx_http_btp_insert_ts(result, key, request->request_total) ) {
          ngx_array_destroy(result);
          ngx_pfree(r->pool, key);
          return NULL;
        }
        ngx_pfree(r->pool, key);
        //------------------------internal prefix------------
        key = make_service_op(r, lcf->internalname, 0, &key_len);
        if( ngx_http_btp_prepare_upstream_counters(request, r, result, key_len, key) )
        {
          ngx_array_destroy(result);
          ngx_pfree(r->pool, key);
          return NULL;
        }
        ngx_pfree(r->pool, key);
        //------------------------content prefix------------
        key = make_service_op(r, lcf->contentname, 0, &key_len);
        if( ngx_http_btp_prepare_content_counters(request, r, result, key_len, key) )
        {
          ngx_array_destroy(result);
          ngx_pfree(r->pool, key);
          return NULL;
        }
        ngx_pfree(r->pool, key);
      }
      //------------------- end --------------------------------

      //------------------- script~~script1.phtml~~service2~~op2 --------------------------------
      {
        key = make_script_service_op(r, request->script_name, lcf->groupname, ngx_strlen(operation), &key_len);
        dest = key + key_len - ngx_strlen(operation);
        memcpy(dest, operation, ngx_strlen(operation));
        if( ngx_http_btp_insert_ts(result, key, request->request_total) )
        {
          ngx_array_destroy(result);
          ngx_pfree(r->pool, key);
          return NULL;
        }
        ngx_pfree(r->pool, key);
        //------------------------internal prefix------------
        key = make_script_service_op(r, request->script_name, lcf->internalname, 0, &key_len);
        if( ngx_http_btp_prepare_upstream_counters(request, r, result, key_len, key) )
        {
          ngx_array_destroy(result);
          ngx_pfree(r->pool, key);
          return NULL;
        }
        ngx_pfree(r->pool, key);
        //------------------------content prefix------------
        key = make_script_service_op(r, request->script_name, lcf->contentname, 0, &key_len);
        if( ngx_http_btp_prepare_content_counters(request, r, result, key_len, key) )
        {
          ngx_array_destroy(result);
          ngx_pfree(r->pool, key);
          return NULL;
        }
        ngx_pfree(r->pool, key);
      }
      //------------------- end --------------------------------
  }

  return result;
}

static size_t ngx_http_btp_get_packed_size(ngx_array_t *request_array)
{
  size_t i, j, result = 0;
  ngx_btp2_request_item* item;

  result += btp_key_opener.len + btp_key_closer.len
    + request_array->nelts * ( btp_key_item_open.len + btp_key_item_cl.len + btp_key_item_close.len + btp_key_comma.len )
    - btp_key_comma.len;

  for(i = 0; i < request_array->nelts; i++)
  {
    item = request_array->elts;
    item = &item[i];
    result += ngx_strlen(item->key) + (item->timers_used - 1) * btp_key_comma.len;
    for( j = 0; j < item->timers_used; j++)
    {
      result += ngx_strlen(ngx_http_btp_itoa(item->timers[j]));
    }
  }

  return result;
}

static void ngx_http_btp_get_packed_data(ngx_array_t *request_array, uint8_t *buf)
{
  size_t i, j;
  char *timer;

  memcpy(buf, btp_key_opener.data, btp_key_opener.len);
  buf += btp_key_opener.len;

  ngx_btp2_request_item* item;
  for(i = 0; i < request_array->nelts; i++)
  {
    item = request_array->elts;
    item = &item[i];

    //{ "name":"
    memcpy(buf, btp_key_item_open.data, btp_key_item_open.len);
    buf += btp_key_item_open.len;

    //key
    memcpy(buf, item->key, ngx_strlen(item->key));
    buf += ngx_strlen(item->key);

    //", "cl":[
    memcpy(buf, btp_key_item_cl.data, btp_key_item_cl.len);
    buf += btp_key_item_cl.len;

    for( j = 0; j < item->timers_used; j++)
    {
      timer = ngx_http_btp_itoa(item->timers[j]);

      //timer
      memcpy(buf, timer, ngx_strlen(timer) );
      buf += ngx_strlen(timer);

      //,
      memcpy(buf, btp_key_comma.data, btp_key_comma.len );
      buf += btp_key_comma.len;
    }

    buf -= btp_key_comma.len;

    //]}
    memcpy(buf, btp_key_item_close.data, btp_key_item_close.len );
    buf += btp_key_item_close.len;

    //,
    memcpy(buf, btp_key_comma.data, btp_key_comma.len );
    buf += btp_key_comma.len;
  }

  buf -= btp_key_comma.len;

  //]}}\r\n
  memcpy(buf, btp_key_closer.data, btp_key_closer.len );
  buf += btp_key_closer.len;
}

static int ngx_http_btp_send_data(ngx_http_btp_loc_conf_t *lcf, ngx_http_request_t *r)
{
  size_t packed_size;
  uint8_t *buf;
  int res;

  ngx_array_t *request_array = ngx_http_btp_prepare_btp2_request(lcf, r);
  if( !request_array )
  {
    return 0;
  }

  //размер запроса
  packed_size = ngx_http_btp_get_packed_size(request_array);
  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "btp handler packed size %i", packed_size);

  buf = ngx_pcalloc(r->pool, packed_size + 1);

  //генерим запрос
  ngx_http_btp_get_packed_data(request_array, buf);
  buf[packed_size] = '\0';
  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "btp handler packed data\n%s", buf);

  res = sendto(lcf->socket.fd, buf, packed_size, 0,
    (struct sockaddr *) &lcf->socket.sockaddr, lcf->socket.sockaddr_len);

  ngx_pfree(r->pool, buf);
  ngx_array_destroy(request_array);

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "btp handler send data %i", res);
  return res;
}

ngx_int_t ngx_http_btp_handler(ngx_http_request_t *r)
{
  ngx_http_btp_loc_conf_t  *lcf;
  ngx_uint_t status, i, j, k, l, *pcode;
  ngx_int_t skip_slashes;

  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http btp handler");

  lcf = ngx_http_get_module_loc_conf(r, ngx_http_btp_module);

  // bail out right away if disabled
  if (lcf->enable == 0)
  {
    return NGX_OK;
  }

  status = 0;
  if (r->err_status)
  {
    status = r->err_status;
  }
  else if (r->headers_out.status)
  {
    status = r->headers_out.status;
  }

  // first check if the status is ignored
  if (status > 0 && lcf->ignore_codes)
  {
    pcode = lcf->ignore_codes->elts;
    for (i = 0; i < lcf->ignore_codes->nelts; i++)
    {
      if (status == pcode[i])
      {
        return NGX_OK;
      }
    }
  }

  if (lcf->socket.fd < 0)
  {
    // no socket -> no data
    return NGX_OK; // doesn't matter, the return status is ignored anyway
  }

  //обработаем данные этого запроса
  {
    char hostname[BTP_STR_BUFFER_SIZE] = {0}, server_name[BTP_STR_BUFFER_SIZE] = {0}/*, script_name[BTP_STR_BUFFER_SIZE] = {0}*/;
    ngx_time_t *tp;
    uint64_t request_total;

    if (lcf->hostname[0] == '\0')
    {
      if (gethostname(hostname, sizeof(hostname)) == 0)
      {
        memcpy(lcf->hostname, hostname, BTP_STR_BUFFER_SIZE - 1);
        memcpy(lcf->groupname, "Nginx_Codes_", sizeof("Nginx_Codes_"));
        memcpy(lcf->internalname, "Nginx_Internal_", sizeof("Nginx_Internal_"));
        memcpy(lcf->contentname, "Nginx_Content_", sizeof("Nginx_Content_"));
        for(
          i = 0, j = strlen("Nginx_Codes_"), k = strlen("Nginx_Internal_"), l = strlen("Nginx_Content_");
          i < BTP_STR_BUFFER_SIZE && lcf->hostname[i] != '\0';
          ++i
        )
        {
          if(lcf->hostname[i] > '9' || lcf->hostname[i] < '0')
          {
            lcf->groupname[j] = lcf->hostname[i];
            lcf->internalname[k] = lcf->hostname[i];
            lcf->contentname[l] = lcf->hostname[i];
            j++;
            k++;
            l++;
          }
        }
      }
      else
      {
        memcpy(lcf->hostname, "unknown", sizeof("unknown"));
        memcpy(lcf->groupname, "Nginx_Codes_unknown", sizeof("Nginx_Codes_unknown"));
        memcpy(lcf->internalname, "Nginx_Internal_unknown", sizeof("Nginx_Internal_unknown"));
        memcpy(lcf->contentname, "Nginx_Content_unknown", sizeof("Nginx_Content_unknown"));
      }
    }

    memcpy(server_name, r->headers_in.server.data, (r->headers_in.server.len > BTP_STR_BUFFER_SIZE) ? BTP_STR_BUFFER_SIZE : r->headers_in.server.len);
        
    //время выполнения запроса
    tp = ngx_timeofday();
    request_total = ((tp->sec - r->start_sec) * 1000000 + (tp->msec - r->start_msec) * 1000);

    if ( lcf->request_buffer_used < BTP_REQUEST_BUFFER_SIZE )
    {
      ngx_http_btp_custom_ctx_t *p;
      p = ngx_http_get_module_ctx(r, ngx_http_btp_module);

      ngx_btp_request *request = &lcf->request_buffer[lcf->request_buffer_used];
      lcf->request_buffer_used += 1;

      request->status = status;
      request->request_total = request_total;

      skip_slashes = (lcf->skip_slashes == NGX_CONF_UNSET) ? 0 : lcf->skip_slashes;
      ngx_http_btp_get_scriptname(status, r, request->script_name, skip_slashes);

      if(r->upstream_receive_finish_sec) {
        request->flags |= BTP_FLAG_CLIENT_SEND;
        request->client_send =
            (r->upstream_receive_finish_sec - r->start_sec) * 1000000 +
            (r->upstream_receive_finish_msec - r->start_msec) * 1000;
      }
            
      if(r->upstream_send_start_sec && r->upstream_send_finish_sec) {
        request->flags |= BTP_FLAG_UPSTREAM_SEND;
        request->upstream_send =
            (r->upstream_send_finish_sec - r->upstream_send_start_sec) * 1000000 +
            (r->upstream_send_finish_msec - r->upstream_send_start_msec) * 1000;
      }

      if(r->upstream_receive_start_sec && r->upstream_receive_finish_sec) {
        request->flags |= BTP_FLAG_UPSTREAM_RECEIVE;
        request->upstream_receive =
            (r->upstream_receive_finish_sec - r->upstream_receive_start_sec) * 1000000 +
            (r->upstream_receive_finish_msec - r->upstream_receive_start_msec) * 1000;
      }

      if(r->upstream_send_start_sec) {
        request->flags |= BTP_FLAG_CLIENT_RECEIVE;
        request->client_receive =
            (tp->sec - r->upstream_send_start_sec) * 1000000 +
            (tp->msec - r->upstream_send_start_msec) * 1000;
      }
      else if( p != NULL
        && p->cliend_send_header_finish_sec
        && r->upstream == NULL
      ) {
        request->flags |= BTP_FLAG_CLIENT_RECEIVE_STATIC;
        request->client_receive_static =
            (tp->sec - p->cliend_send_header_finish_sec) * 1000000 +
            (tp->msec - p->cliend_send_header_finish_msec) * 1000;
      }

      request->upstream_total = r->upstream_total_sec * 1000000 + r->upstream_total_msec * 1000;

      if( p != NULL && p->cliend_send_header_finish_sec ) {
        request->client_send_header =
          (p->cliend_send_header_finish_sec - r->start_sec) * 1000000 +
          (p->cliend_send_header_finish_msec - r->start_msec) * 1000;
      }

      request->request_size = r->request_length;
      request->response_size = r->connection->sent;
      if (
        r->headers_out.content_encoding != NULL
        && r->headers_out.content_encoding->value.len == 4
        && ngx_strncasecmp(r->headers_out.content_encoding->value.data,(u_char *) "gzip", 4) == 0
      ) {
        request->response_gzip_size = r->connection->sent;
      }

      if( p != NULL ) {
        p->cliend_send_header_finish_sec = 0;
        p->cliend_send_header_finish_msec = 0;
      }
    }
        
    //отправим буферизованные запросы
    if(lcf->request_buffer_used >= BTP_REQUEST_BUFFER_SIZE)
    {
      for(i = 0; i < BTP_REQUEST_BUFFER_SIZE; i++)
      {
        ngx_log_debug5(
          NGX_LOG_DEBUG_HTTP,
          r->connection->log,
          0,
          "btp handler request op:%i ts:%i script:%s hostname:%s groupname:%s",
          lcf->request_buffer[i].status,
          lcf->request_buffer[i].request_total,
          lcf->request_buffer[i].script_name,
          lcf->hostname,
          lcf->groupname
        );
      }
            
      ngx_http_btp_send_data(lcf, r);
      lcf->request_buffer_used = 0;
    }
  }

	return NGX_OK;
}

ngx_int_t ngx_http_btp_post_access_handler(ngx_http_request_t *r)
{
  ngx_http_btp_custom_ctx_t *p;
  p = ngx_http_get_module_ctx(r, ngx_http_btp_module);
  if (p == NULL) {
    p = ngx_pcalloc(r->pool, sizeof(ngx_http_btp_custom_ctx_t));
    if (p == NULL)
    {
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_http_set_ctx(r, p, ngx_http_btp_module);
  }

  ngx_time_t *tp = ngx_timeofday();
  p->cliend_send_header_finish_sec = tp->sec;
  p->cliend_send_header_finish_msec = tp->msec;

  return NGX_DECLINED;
}

static void ngx_http_btp_get_fastcgi_scriptname(ngx_http_request_t *r, ngx_str_t *result)
{
  size_t size, len, key_len, val_len;
  ngx_uint_t i, n, next, hash, skip_empty;
  ngx_buf_t *b;
  ngx_http_script_code_pt code;
  ngx_http_script_engine_t e, le;
  ngx_http_btp_fastcgi_loc_conf_t *flcf;
  ngx_http_script_len_code_pt lcode;

  len = 0;
  flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);
  if (flcf->params_len)
  {
    ngx_memzero(&le, sizeof(ngx_http_script_engine_t));
    ngx_http_script_flush_no_cacheable_variables(r, flcf->flushes);
    le.flushed = 1;

    le.ip = flcf->params_len->elts;
    le.request = r;

    while (*(uintptr_t *) le.ip)
    {
      lcode = *(ngx_http_script_len_code_pt *) le.ip;
      key_len = lcode(&le);

      lcode = *(ngx_http_script_len_code_pt *) le.ip;
      skip_empty = lcode(&le);

      for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le))
      {
        lcode = *(ngx_http_script_len_code_pt *) le.ip;
      }
      le.ip += sizeof(uintptr_t);

      if (skip_empty && val_len == 0)
      {
        continue;
      }

      len += 1 + key_len + ((val_len > 127) ? 4 : 1) + val_len;
    }

    size = len + 32;
    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
      return;
    }

    ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

    e.ip = flcf->params->elts;
    e.pos = b->last;
    e.request = r;
    e.flushed = 1;

    le.ip = flcf->params_len->elts;

    while (*(uintptr_t *) le.ip)
    {
      lcode = *(ngx_http_script_len_code_pt *) le.ip;
      key_len = (u_char) lcode(&le);

      lcode = *(ngx_http_script_len_code_pt *) le.ip;
      skip_empty = lcode(&le);

      for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le))
      {
        lcode = *(ngx_http_script_len_code_pt *) le.ip;
      }
      le.ip += sizeof(uintptr_t);

      if (skip_empty && val_len == 0)
      {
        e.skip = 1;
        while (*(uintptr_t *) e.ip)
        {
          code = *(ngx_http_script_code_pt *) e.ip;
          code((ngx_http_script_engine_t *) &e);
        }
        e.ip += sizeof(uintptr_t);
        e.skip = 0;
        continue;
      }

      *e.pos++ = (u_char) key_len;
      if (val_len > 127)
      {
        *e.pos++ = (u_char) (((val_len >> 24) & 0x7f) | 0x80);
        *e.pos++ = (u_char) ((val_len >> 16) & 0xff);
        *e.pos++ = (u_char) ((val_len >> 8) & 0xff);
        *e.pos++ = (u_char) (val_len & 0xff);

      }
      else
      {
        *e.pos++ = (u_char) val_len;
      }

      while (*(uintptr_t *) e.ip)
      {
        code = *(ngx_http_script_code_pt *) e.ip;
        code((ngx_http_script_engine_t *) &e);
      }
      e.ip += sizeof(uintptr_t);

      ngx_log_debug4(
        NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "BTPPPP fastcgi param: \"%*s: %*s\"",
        key_len, e.pos - (key_len + val_len),
        val_len, e.pos - val_len
      );

      if(
        key_len == btp_fastcgi_scriptname_param.len
        && strncmp((const char *)(e.pos - (key_len + val_len)), (const char *)(btp_fastcgi_scriptname_param.data), key_len) == 0
      )
      {
        //переопределение
        if( result->data != NULL )
        {
          ngx_pfree(r->pool, result->data);
          result->data = NULL;
        }

        result->data = ngx_pcalloc(r->pool, val_len + 1);
        if( result->data != NULL )
        {
          result->len = val_len;
          memcpy(result->data, e.pos - val_len, val_len);
          result->data[val_len] = '\0';
        }
      }
    }
  }
}

static void ngx_http_btp_get_scriptname(ngx_uint_t status, ngx_http_request_t *r, char result[BTP_STR_BUFFER_SIZE], ngx_int_t skip_slashes)
{
  ngx_str_t *scriptname;
  size_t scriptname_len = 0;
  char *num;
  int i;

  //бизнес-логика, чтобы btp не сдох
  memset(result, '\0', BTP_STR_BUFFER_SIZE);

  if( status != 404 )
  {
    //upstream requests
    if( r->upstream )
    {
      scriptname = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
      if( scriptname != NULL )
      {
        scriptname->data = NULL;
        ngx_http_btp_get_fastcgi_scriptname(r, scriptname);
        if( scriptname->len > 0)
        {
          u_char *name_start = scriptname->data;
          u_char *name_finish = scriptname->data + scriptname->len;

          ngx_log_debug3(
            NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "BTP fastcgi scriptname source: \"%*s\" skip: %i",
            scriptname->len, scriptname->data, skip_slashes
          );

          //skip some slashes data
          while( skip_slashes > 0 ) {
            u_char *result = ngx_strlchr(name_start, name_finish, '/');
            if( result == NULL ) {
              break;
            }
            name_start = result + 1;
            --skip_slashes;
          }

          if( name_finish > name_start ) {
            scriptname_len = name_finish - name_start;
            scriptname_len = (scriptname_len >= BTP_STR_BUFFER_SIZE)
              ? BTP_STR_BUFFER_SIZE - 1 : scriptname_len;
            memcpy(result, name_start, scriptname_len);
          }
          ngx_pfree(r->pool, scriptname->data);
        }
        ngx_pfree(r->pool, scriptname);
      }
    }
  }

  if( scriptname_len < 1 )
  {
    memcpy(result, "unknown_", sizeof("unknown_"));
    num = ngx_http_btp_itoa(status);
    memcpy(result + strlen("unknown_"), num, strlen(num));
  }

  ngx_log_debug1(
      NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
      "btp script name variable: %s",
      result
  );
}

static void *ngx_http_btp_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_btp_loc_conf_t  *conf;
    
	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_btp_loc_conf_t));
	if (conf == NULL)
	{
		return NULL;
	}

	conf->enable = NGX_CONF_UNSET;
	conf->ignore_codes = NULL;
	conf->socket.fd = -1;
	conf->buffer_size = NGX_CONF_UNSET_SIZE;
  conf->request_buffer_used = 0;
  conf->skip_slashes = NGX_CONF_UNSET;

	return conf;
}

static char *ngx_http_btp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_btp_loc_conf_t *prev = parent;
	ngx_http_btp_loc_conf_t *conf = child;

	ngx_conf_merge_value(conf->enable, prev->enable, 0);
	ngx_conf_merge_value(conf->skip_slashes, prev->skip_slashes, 4);

	if (conf->ignore_codes == NULL)
	{
		conf->ignore_codes = prev->ignore_codes;
	}

	if (conf->server.host.data == NULL && conf->server.port_text.data == NULL)
	{
		conf->server = prev->server;
	}

	if (conf->socket.fd == -1)
	{
		conf->socket = prev->socket;
	}
	
	if (conf->buffer_size == NGX_CONF_UNSET_SIZE)
	{
		conf->buffer_size = prev->buffer_size;
		conf->buffer_used_len = 0;
		conf->buffer = NULL;
	}

	if (conf->hostname[0] == '\0' && prev->hostname[0] != '\0')
	{
		memcpy(conf->hostname, prev->hostname, sizeof(prev->hostname));
	}

	return NGX_CONF_OK;
}

static ngx_int_t ngx_http_btp_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
	if (h == NULL)
	{
		return NGX_ERROR;
	}
	*h = ngx_http_btp_handler;

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL)
  {
    return NGX_ERROR;
  }
  *h = ngx_http_btp_post_access_handler;

	return NGX_OK;
}
