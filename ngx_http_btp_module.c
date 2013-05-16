/*
 * based on ngx_http_pinba_module by Antony Dovgal, 
 */

/*
 
 
 В конфигурации nginx модуль включается так
 
 http {
    btp_enable on;
    btp_server 127.0.0.1:40000;
 
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

extern ngx_module_t  ngx_http_fastcgi_module;

typedef enum {
    ngx_http_fastcgi_st_version = 0,
    ngx_http_fastcgi_st_type,
    ngx_http_fastcgi_st_request_id_hi,
    ngx_http_fastcgi_st_request_id_lo,
    ngx_http_fastcgi_st_content_length_hi,
    ngx_http_fastcgi_st_content_length_lo,
    ngx_http_fastcgi_st_padding_length,
    ngx_http_fastcgi_st_reserved,
    ngx_http_fastcgi_st_data,
    ngx_http_fastcgi_st_padding
} fastcgi_state_e_copy_t;

typedef struct {
    fastcgi_state_e_copy_t       state;
    u_char                        *pos;
    u_char                        *last;
    ngx_uint_t                     type;
    size_t                         length;
    size_t                         padding;

    unsigned                       fastcgi_stdout:1;
    unsigned                       large_stderr:1;

    ngx_array_t                   *split_parts;

    ngx_str_t                      script_name;
    ngx_str_t                      path_info;
} fastcgi_context_copy_t;

#define BTP_STR_BUFFER_SIZE 257
#define BTP_REQUEST_BUFFER_SIZE 10

typedef struct {
    ngx_uint_t status;
    char script_name[BTP_STR_BUFFER_SIZE];
    uint64_t ts;
} ngx_btp_request;

typedef struct {
	ngx_flag_t   enable;
	ngx_array_t *ignore_codes;
	ngx_url_t    server;
	char        *buffer;
	size_t       buffer_size;
	size_t       buffer_used_len;
    ngx_btp_request request_buffer[BTP_STR_BUFFER_SIZE];
    size_t       request_buffer_used;
	struct {
        int fd;
        struct sockaddr_storage sockaddr;
        int sockaddr_len;
	} socket;
	char hostname[BTP_STR_BUFFER_SIZE];
    char groupname[BTP_STR_BUFFER_SIZE];
} ngx_http_btp_loc_conf_t;

static void *ngx_http_btp_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_btp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_btp_init(ngx_conf_t *cf);
static char *ngx_http_btp_ignore_codes(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_btp_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void ngx_http_btp_get_scriptname(ngx_uint_t status, ngx_http_request_t *r, char *result);    

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

    ngx_null_command
};

static ngx_http_module_t  ngx_http_btp_module_ctx = {
    NULL,                   // preconfiguration
    ngx_http_btp_init,              // postconfiguration

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

	if (cf->args->nelts == 1 && ngx_strcmp(&value[1], "none") == 0) {
		lcf->ignore_codes = NULL;
		return NGX_OK;
	}

	if (lcf->ignore_codes == NULL) {
		lcf->ignore_codes = ngx_array_create(cf->pool, 4, sizeof(ngx_uint_t));
		if (lcf->ignore_codes == NULL) {
			return NGX_CONF_ERROR;
		}
	}

	for (i = 1; i < cf->args->nelts; i++) {
		char *dash;

		dash = ngx_strchr(value[i].data, '-');
		if (dash) {
			// a range of values
			u_char *data_copy, *dash_copy;
			int code1_len, code2_len, n;
			ngx_int_t code1, code2;

			code1_len = (dash - (char *)value[i].data);
			code2_len = value[i].len - code1_len;

			if (code1_len < 3 || code2_len < 3) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid status code value \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			data_copy = ngx_pstrdup(cf->pool, &value[i]);
			dash_copy = data_copy + code1_len;
			*dash_copy = '\0';
			
			code1 = ngx_atoi(data_copy, code1_len);
			if (code1 < 100 || code1 > 599) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid status code value \"%V\", values must not be less than 100 or greater than 599", &value[i]);
				return NGX_CONF_ERROR;
			}
			
			code2 = ngx_atoi(dash_copy + 1, code2_len - 1);
			if (code2 < 100 || code2 > 599) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid status code value \"%V\", values must not be less than 100 or greater than 599", &value[i]);
				return NGX_CONF_ERROR;
			}

			if (code1 >= code2) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid status code value \"%V\", range end must be greater than range start", &value[i]);
				return NGX_CONF_ERROR;
			}

			for (n = code1; n <= code2; n++) {
				pcode = ngx_array_push(lcf->ignore_codes);
				if (pcode == NULL) {
					return NGX_CONF_ERROR;
				}
				*pcode = (ngx_uint_t)n;
			}


		} else {
			// just a simple value
			code = ngx_atoi(value[i].data, value[i].len);
			if (code < 100 || code > 599) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid status code value \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			pcode = ngx_array_push(lcf->ignore_codes);
			if (pcode == NULL) {
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

	value = cf->args->elts;

	ngx_memzero(&u, sizeof(ngx_url_t));

	u.url = value[1];
	u.no_resolve = 0;

	if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
		if (u.err) {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "%s in btp server \"%V\"", u.err, &u.url);
		}
		return NGX_CONF_ERROR;
	}

	if (u.no_port) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "no port in btp server \"%V\"", &u.url);
		return NGX_CONF_ERROR;
	}

	lcf->socket.fd = -1;
	lcf->server = u;

	if (lcf->server.host.len > 0 && lcf->server.host.data != NULL) {
		lcf->server.host.data[lcf->server.host.len] = '\0';
	}

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
	status = getaddrinfo((char *)lcf->server.host.data, (char *)lcf->server.port_text.data, &ai_hints, &ai_list);
	if (status != 0) {
		ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "btp module: getaddrinfo(\"%V\") failed: %s", &lcf->server.url, gai_strerror(status));
		return NGX_CONF_ERROR;
	}

	fd = -1;
	for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) {
		fd = socket(ai_ptr->ai_family, ai_ptr->ai_socktype, ai_ptr->ai_protocol);
		if (fd >= 0) {
			lcf->socket.fd = fd;
			memcpy(&lcf->socket.sockaddr, ai_ptr->ai_addr, ai_ptr->ai_addrlen);
			lcf->socket.sockaddr_len = ai_ptr->ai_addrlen;
			break;
		}
	}

	freeaddrinfo(ai_list);
	if (fd < 0) {
		ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "btp module: socket() failed: %s", strerror(errno));
		return NGX_CONF_ERROR;
	}
	return NGX_CONF_OK;
}

static char* ngx_http_btp_itoa(uint64_t val){
	
	static char buf[32] = {0};	
	int i = 30;
    
    if(val == 0) {
        buf[i] = '0';
        --i;
    }
	else {
        for(; val && i ; --i, val /= 10) {
            buf[i] = "0123456789"[val % 10];
        }
    }
	
	return &buf[i+1];	
}

/*
{"jsonrpc":"2.0","method":"put","params":{"script":"clside:other","items":{"clientside_stat_hostname":{"cr":{"js_loaded":[247000],"dom_ready":[424000],"window_loaded":[736000],"custom":[0]}}}}}
{"jsonrpc":"2.0","method":"put","params":{"script":"/diary/post.phtml","items":{"Nginx_Codes_wwwnew":{"wwwnew34":{"302":[500]}}}}}
 */

ngx_str_t btp_jsonrpc = ngx_string("{\"jsonrpc\":\"2.0\",\"method\":\"put\",\"params\":{\"script\":\""),
    btp_items =  ngx_string("\",\"items\":{\"Nginx_Codes_"),
    btp_separator_open_curl = ngx_string("\":{\""),
    btp_separator_open_brak = ngx_string("\":["),
    btp_ending = ngx_string("]}}}}}\r\n");

static size_t ngx_http_btp_get_packed_size (const ngx_http_btp_loc_conf_t *lcf) {
    size_t i, common_size, size = 0;
    char *num;
    
    //общий размер, который не зависит от данных
    common_size = btp_jsonrpc.len + btp_items.len + 2 * btp_separator_open_curl.len + btp_separator_open_brak.len + btp_ending.len;
    
    for(i = 0; i < BTP_REQUEST_BUFFER_SIZE; i++) {        
        
        size += common_size + ngx_strlen(lcf->request_buffer[i].script_name) + ngx_strlen(lcf->groupname) + ngx_strlen(lcf->hostname);
        
        num = ngx_http_btp_itoa(lcf->request_buffer[i].status);
        size += ngx_strlen(num);
        
        num = ngx_http_btp_itoa(lcf->request_buffer[i].ts);
        size += ngx_strlen(num);
    }
    
    return size;
}

static void ngx_http_btp_get_packed_data(ngx_http_btp_loc_conf_t *lcf, uint8_t *buf) {
    uint8_t *dest = buf;
    size_t i, len;
    char *num;
    
    for(i = 0; i < BTP_REQUEST_BUFFER_SIZE; i++) {        
        
        // {"jsonrpc":"2.0","method":"put","params":{"script":"
        memcpy(dest, btp_jsonrpc.data, btp_jsonrpc.len);
        dest += btp_jsonrpc.len;
        
        // /diary/post.phtml
        len = ngx_strlen(lcf->request_buffer[i].script_name);
        memcpy(dest, lcf->request_buffer[i].script_name, len);
        dest += len;
        
        // ","items":{"Nginx_Codes_
        memcpy(dest, btp_items.data, btp_items.len);
        dest += btp_items.len;
        
        // wwwnew
        len = ngx_strlen(lcf->groupname);
        memcpy(dest, lcf->groupname, len);
        dest += len;
        
        // ":{"
        memcpy(dest, btp_separator_open_curl.data, btp_separator_open_curl.len);
        dest += btp_separator_open_curl.len;
        
        // wwwnew34
        len = ngx_strlen(lcf->hostname);
        memcpy(dest, lcf->hostname, len);
        dest += len;
        
        // ":{"
        memcpy(dest, btp_separator_open_curl.data, btp_separator_open_curl.len);
        dest += btp_separator_open_curl.len;
        
        // 302
        num = ngx_http_btp_itoa(lcf->request_buffer[i].status);
        len = ngx_strlen(num);
        memcpy(dest, num, len);
        dest += len;        
        
        // ":[
        memcpy(dest, btp_separator_open_brak.data, btp_separator_open_brak.len);
        dest += btp_separator_open_brak.len;
        
        // 500
        num = ngx_http_btp_itoa(lcf->request_buffer[i].ts);
        len = ngx_strlen(num);
        memcpy(dest, num, len);
        dest += len; 
        
        // ]}}}}}
        memcpy(dest, btp_ending.data, btp_ending.len);
        dest += btp_ending.len;
    }
}

static int ngx_http_btp_send_data(ngx_http_btp_loc_conf_t *lcf, ngx_http_request_t *r)
{
    size_t packed_size;
    uint8_t *buf;
	int res;
     
    //размер запроса
    packed_size = ngx_http_btp_get_packed_size(lcf);   
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "btp handler packed size %i", packed_size);

	buf = ngx_pcalloc(r->pool, packed_size);
    
    //генерим запрос
	ngx_http_btp_get_packed_data(lcf, buf);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "btp handler packed data\n%s", buf);

	res = sendto(lcf->socket.fd, buf, packed_size, 0,
				(struct sockaddr *) &lcf->socket.sockaddr, lcf->socket.sockaddr_len);
	ngx_pfree(r->pool, buf);
    
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "btp handler send data %i", res);
	return res;
}

ngx_int_t ngx_http_btp_handler(ngx_http_request_t *r)
{
    ngx_http_btp_loc_conf_t  *lcf;
    ngx_uint_t status, i, j, *pcode;   

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http btp handler");

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_btp_module);

    // bail out right away if disabled
    if (lcf->enable == 0) {
        return NGX_OK;
    }

    status = 0;

    if (r->err_status) {
        status = r->err_status;
    } else if (r->headers_out.status) {
        status = r->headers_out.status;
    }

    // first check if the status is ignored
    if (status > 0 && lcf->ignore_codes) {
        pcode = lcf->ignore_codes->elts;
        for (i = 0; i < lcf->ignore_codes->nelts; i++) {
            if (status == pcode[i]) {
                return NGX_OK;
            }
        }
    }

    if (lcf->socket.fd < 0) {
        // no socket -> no data
        return NGX_OK; // doesn't matter, the return status is ignored anyway
    }
    
    //обработаем данные этого запроса
    {
        char hostname[BTP_STR_BUFFER_SIZE] = {0}, server_name[BTP_STR_BUFFER_SIZE] = {0}/*, script_name[BTP_STR_BUFFER_SIZE] = {0}*/;
        ngx_time_t *tp;
        uint64_t ms;    

        if (lcf->hostname[0] == '\0') {
            if (gethostname(hostname, sizeof(hostname)) == 0) {
                memcpy(lcf->hostname, hostname, BTP_STR_BUFFER_SIZE - 1);                
                for(i = 0, j = 0; i < BTP_STR_BUFFER_SIZE && lcf->hostname[i] != '\0'; i++) {
                    if(lcf->hostname[i] > '9' || lcf->hostname[i] < '0') {
                        lcf->groupname[j] = lcf->hostname[i];
                        j++;
                    }
                }
            } else {
                memcpy(lcf->hostname, "unknown", sizeof("unknown"));
                memcpy(lcf->groupname, "unknown", sizeof("unknown"));
            }                        
        }

        memcpy(server_name, r->headers_in.server.data, (r->headers_in.server.len > BTP_STR_BUFFER_SIZE) ? BTP_STR_BUFFER_SIZE : r->headers_in.server.len);
        
        //время выполнения запроса
        tp = ngx_timeofday();
		ms = ((tp->sec - r->start_sec) * 1000000 + (tp->msec - r->start_msec) * 1000); 

        if (lcf->request_buffer_used < BTP_REQUEST_BUFFER_SIZE) {
            ngx_btp_request *request = &lcf->request_buffer[lcf->request_buffer_used];
                        
            request->status = status;
            request->ts = ms;
            ngx_http_btp_get_scriptname(status, r, request->script_name);
            
            lcf->request_buffer_used += 1;
        }
        
        //отправим буферизованные запросы
        if(lcf->request_buffer_used >= BTP_REQUEST_BUFFER_SIZE) {           
            for(i = 0; i < BTP_REQUEST_BUFFER_SIZE; i++) {                                 
                ngx_log_debug5(
                    NGX_LOG_DEBUG_HTTP,
                    r->connection->log,
                    0,
                    "btp handler request op:%i ts:%i script:%s hostname:%s groupname:%s",
                    lcf->request_buffer[i].status,
                    lcf->request_buffer[i].ts,
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

static void ngx_http_btp_get_scriptname(ngx_uint_t status, ngx_http_request_t *r, char result[BTP_REQUEST_BUFFER_SIZE])
{
    ngx_str_t *scriptname = NULL;
    size_t scriptname_len = 0;
    fastcgi_context_copy_t  *f;
    char *num;

    f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);
    if ( f != NULL && f->script_name.len > 0 ) {
        scriptname = &f->script_name;
        scriptname_len = (scriptname->len >= BTP_STR_BUFFER_SIZE) ? BTP_STR_BUFFER_SIZE - 1 : scriptname->len;
    }
           
    //бизнес-логика, чтобы btp не сдох
	memset(result, '\0', BTP_STR_BUFFER_SIZE);           

    if( scriptname_len > 0 ) {
        memcpy(result, scriptname->data, scriptname_len);
    }
    else {
        memcpy(result, "unknown_", sizeof("unknown_"));
        num = ngx_http_btp_itoa(status);
        memcpy(result + strlen("unknown_"), num, strlen(num));
    }
}

static void *ngx_http_btp_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_btp_loc_conf_t  *conf;
    
	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_btp_loc_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	conf->enable = NGX_CONF_UNSET;
	conf->ignore_codes = NULL;
	conf->socket.fd = -1;
	conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->request_buffer_used = 0;

	return conf;
}

static char *ngx_http_btp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_btp_loc_conf_t *prev = parent;
	ngx_http_btp_loc_conf_t *conf = child;

	ngx_conf_merge_value(conf->enable, prev->enable, 0);

	if (conf->ignore_codes == NULL) {
		conf->ignore_codes = prev->ignore_codes;
	}

	if (conf->server.host.data == NULL && conf->server.port_text.data == NULL) {
		conf->server = prev->server;
	}

	if (conf->socket.fd == -1) {
		conf->socket = prev->socket;
	}
	
	if (conf->buffer_size == NGX_CONF_UNSET_SIZE) {
		conf->buffer_size = prev->buffer_size;
		conf->buffer_used_len = 0;
		conf->buffer = NULL;
	}

	if (conf->hostname[0] == '\0' && prev->hostname[0] != '\0') {
		memcpy(conf->hostname, prev->hostname, sizeof(prev->hostname));
	}

	return NGX_CONF_OK;
}

static ngx_int_t ngx_http_btp_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_btp_handler;

	return NGX_OK;
}