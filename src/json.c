#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include "json.h"


static void skip_ws(const char* json,size_t len, size_t *i);
static int parse_string(const char  *json,size_t len,struct Json_token *t, size_t *i);
static int parse_number(const char  *json,size_t len,struct Json_token *t, size_t *i);
static int parse_literal(const char  *json,size_t len,struct Json_token *t, size_t *i);

int json_parser(const char *json, size_t len,struct Json_token *tokens, size_t max_tokens)
{
	if(!json || !tokens || len == 0 || len > INT_MAX) return JSON_INVALID_ERR;

	int state = -1;
	int stack[JSON_MAX_DEPTH];
	int depth = 0;
	memset(stack,-1,JSON_MAX_DEPTH*sizeof(int));
	size_t i = 0;
	int tk_count = 0;

	skip_ws(json,len,&i);
	while(i < len){


		switch(json[i]){
		case '{':
		case '[':
		{

			if(state != -1 && state != VALUE && state != VALUE_OR_CLOSING_OBJECT)
                return JSON_INVALID_ERR;
            if(depth >= JSON_MAX_DEPTH) return JSON_DEPTH_LIMIT_ERR;
            if((size_t)tk_count >= max_tokens) return JSON_TK_LIMIT_ERR;
			tokens[tk_count] = (struct Json_token){0};

			tokens[tk_count].type = json[i] == '{' ? OBJECT_JS : ARRAY_JS;
			tokens[tk_count].start = i;
			tokens[tk_count].size = 0;
			tokens[tk_count].parent = (depth > 0) ? stack[depth -1] : -1;
			if(tokens[tk_count].type == OBJECT_JS) state = KEY_OR_CLOSING_OBJECT;
			if(tokens[tk_count].type == ARRAY_JS)  state = VALUE_OR_CLOSING_OBJECT;
			
			if(depth > 0) tokens[stack[depth-1]].size++;
			stack[depth++] = tk_count;
			tk_count++;
			i++;
			break;
		}
		case '}':
		case ']': 
		{ 

			if( state != KEY_OR_CLOSING_OBJECT 
					&& state != VALUE_OR_CLOSING_OBJECT 
					&& state != COMMA_OR_CLOSING_OBJ) return JSON_INVALID_ERR;
			if(depth == 0) return JSON_INVALID_ERR;
			depth--;
			int expect = json[i] == '}' ? OBJECT_JS : ARRAY_JS;
			if(expect == ARRAY_JS && state == KEY_OR_CLOSING_OBJECT) return JSON_INVALID_ERR;

			if(tokens[stack[depth]].type != expect) return JSON_INVALID_ERR;

			tokens[stack[depth]].end = i + 1;
			if(expect == OBJECT_JS) tokens[stack[depth]].size /= 2;
			int p = tokens[stack[depth]].parent;
			if(p == -1)
				state = END;
			else
				state = COMMA_OR_CLOSING_OBJ;
			i++;
			break;
		}
		case '"':
		{
			if(state == COMMA_OR_CLOSING_OBJ) return JSON_INVALID_ERR;
			if(state != KEY  
					&& state != KEY_OR_CLOSING_OBJECT
					&& state != VALUE
					&& state != VALUE_OR_CLOSING_OBJECT) return JSON_INVALID_ERR;

			if(state == KEY || state == KEY_OR_CLOSING_OBJECT) state = COLON;
			if(state == VALUE || state == VALUE_OR_CLOSING_OBJECT) state = COMMA_OR_CLOSING_OBJ;

			if((size_t)tk_count >= max_tokens) return JSON_TK_LIMIT_ERR;
			tokens[tk_count] = (struct Json_token){0};
			tokens[tk_count].parent = (depth > 0) ? stack[depth -1] : -1;
			if(depth > 0) tokens[stack[depth-1]].size++;
			if(parse_string(json,len,&tokens[tk_count],&i) < 0) return JSON_INVALID_ERR;
			tk_count++;
			break;
		}
		case ',':
		case ':':
		{
			if(state != COLON && state != COMMA_OR_CLOSING_OBJ) return JSON_INVALID_ERR;
			if(state == COLON && json[i] != ':') return JSON_INVALID_ERR; 
			if(state == COMMA_OR_CLOSING_OBJ && json[i] != ',') return JSON_INVALID_ERR; 

			if(json[i] == ':') state = VALUE;
			if(json[i] == ','){
                if(depth == 0) return JSON_INVALID_ERR;
                state = tokens[stack[depth - 1]].type == ARRAY_JS ? VALUE : KEY;
			}

			size_t j = i;
			j++;
			skip_ws(json,len,&j);
			if(j >= len) return JSON_INVALID_ERR;
			if(json[j] == ']' || json[j] == '}' || json[j] == ':') return -1;

			i++;
			break;
		}
		default: /*number or literal*/
			if(state != VALUE && state != VALUE_OR_CLOSING_OBJECT) return JSON_INVALID_ERR;
			if(json[i] == 0x2D || (json[i] >= 0x30 && json[i] <= 0x39)){
				if((size_t)tk_count >= max_tokens) return JSON_TK_LIMIT_ERR;
			tokens[tk_count] = (struct Json_token){0};
				tokens[tk_count].parent = (depth > 0) ? stack[depth -1] : -1;

				if(depth > 0) tokens[stack[depth-1]].size++;

				if(parse_number(json,len,&tokens[tk_count],&i) < 0) return JSON_INVALID_ERR;
				tk_count++;
			}else{
				if((size_t)tk_count >= max_tokens) return JSON_TK_LIMIT_ERR;
			tokens[tk_count] = (struct Json_token){0};
				tokens[tk_count].parent = (depth > 0) ? stack[depth -1] : -1;

				if(depth > 0) tokens[stack[depth-1]].size++;

				if(parse_literal(json,len,&tokens[tk_count],&i) < 0) return JSON_INVALID_ERR;
				tk_count++;
			}
			state = COMMA_OR_CLOSING_OBJ;
			break;
		}
		skip_ws(json,len,&i);
	}


	if(depth != 0 || state != END) return JSON_INVALID_ERR;
	return tk_count;
}


static void skip_ws(const char* json,size_t len, size_t *i)
{
	size_t k = *i;
	while(k < len
			&& (json[k] == SPACE 
				|| json[k] == NEW_LINE 
				|| json[k] == H_TAB
				|| json[k] == CARRIAGE_RETURN)) k++;
	*i = k;
}

static int parse_string(const char  *json,size_t len,struct Json_token *t, size_t *i)
{

	size_t k = *i + 1;
	t->start = (int)k;

	while(k < len){
		unsigned char c = (unsigned char)json[k];

		switch(c){
		case '"':
		{
			t->end = (int)k;
			t->type = STRING_JS;
			*i = k + 1;
			return 0;
		}
		case '\\':
		{
			k++;
			if(k >= len) return JSON_INVALID_ERR;
			switch(json[k]){
			case '"':
			case '\\':
			case '/':
			case 'f':
			case 'r':
			case 't':
			case 'b':
			case 'n':
				k++;
				break;
			case 'u':
				if(k + 4 >= len) return JSON_INVALID_ERR;
				int j = 1;
				while(j<=4) if(!isxdigit((unsigned char)json[k + j++])) return JSON_INVALID_ERR;

				k += 5;
				break;
			default:
				return JSON_INVALID_ERR;
			}
			break;
		}
		default:
			if(c < 0x20) return JSON_INVALID_ERR;
			k++;
			break;
		}

		

	}

	return JSON_INVALID_ERR;
}

static int parse_number(const char  *json,size_t len,struct Json_token *t, size_t *i)
{
	size_t k = *i;
	t->start = (int)k;
	if(k < len && (json[k] == '-' || json[k] == '+')) k++;
	if(k < len && json[k] == '0' &&  k+1 < len && isdigit((unsigned char)json[k+1])) return JSON_INVALID_ERR;

	if(k >= len || !isdigit((unsigned char)json[k])) return JSON_INVALID_ERR; 
	
	while(k < len && isdigit((unsigned char)json[k])) k++;

	if(k < len && json[k] == '.'){
		k++;
		if(k >= len || !isdigit((unsigned char)json[k])) return JSON_INVALID_ERR; 
		while(k < len && isdigit((unsigned char)json[k])) k++;
	}

	if(k < len && (json[k] == 'e' || json[k] == 'E')){
		k++;
		if(k < len && (json[k] == '-' || json[k] == '+')) k++;

		if(k >= len || !isdigit((unsigned char)json[k])) return JSON_INVALID_ERR; 
		while(k < len && isdigit((unsigned char)json[k])) k++;
	}

	t->type = NUMBER_JS;
	t->end = (int)k;
	*i = k;
	return 0;
}

static int parse_literal(const char  *json,size_t len,struct Json_token *t, size_t *i)
{
	size_t k = *i;
	t->start = (int)k;

	/*false, true, null*/
	if(k + 4 <= len && strncmp(&json[k],"true",4) == 0){
		t->type = TRUE_JS;
		k += 4;
	}else if( k + 4 <= len && strncmp(&json[k],"null",4) == 0){
		t->type = NUL_JS;
		k += 4;
	}else if(k + 5 <= len && strncmp(&json[k],"false",5) == 0){
		t->type = FALSE_JS;
		k += 5;
	}else{
		return JSON_INVALID_ERR;
	}

	t->end = (int)k;
	*i = k;
	return 0;
}

int is_token_empty(struct Json_token *t)
{
	return 	t->type == 0 && t->start == 0 
		&& t->end == 0 && t->size == 0 && t->parent == 0;
}

static int hex4(const uint8_t *src, size_t len, uint32_t *value)
{
    if(!src || len < 4) return -1;
    uint32_t n = 0;
    for(size_t i = 0; i < 4; ++i){
        unsigned c = src[i], digit;
        if(c >= '0' && c <= '9') digit = c - '0';
        else if(c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if(c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else return -1;
        n = (n << 4) | digit;
    }
    *value = n;
    return 0;
}

static int utf8(uint32_t cp, uint8_t *dst, size_t dlen)
{
    if(!dst || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return -1;
    size_t n = cp <= 0x7f ? 1 : cp <= 0x7ff ? 2 : cp <= 0xffff ? 3 : 4;
    if(dlen < n) return -1;
    if(n == 1) dst[0] = cp;
    else {
        uint32_t v = cp;
        for(size_t i = n - 1; i > 0; --i){
            dst[i] = 0x80 | (v & 0x3f);
            v >>= 6;
        }
        dst[0] = (n == 2 ? 0xc0 : n == 3 ? 0xe0 : 0xf0) | v;
    }
    return (int)n;
}

/* Writes raw bytes (including embedded NULs), without a C-string terminator.
 * Returns 0 on success, -1 for malformed escapes or insufficient capacity. */
int decode_json_escape(const char *src, size_t slen, char *dst, size_t dlen)
{
    if((!src && slen) || (!dst && slen)) return -1;
    size_t j = 0;
    for(size_t i = 0; i < slen; ++i){
        unsigned char c = src[i];
        if(c == '\\'){
            if(++i == slen) return -1;
            switch(src[i]){
            case '"': c = '"'; break;
            case '/': c = '/'; break;
            case '\\': c = '\\'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'u': {
                uint32_t cp;
                if(hex4((const uint8_t *)src + i + 1, slen - i - 1, &cp)) return -1;
                i += 4;
                if(cp >= 0xd800 && cp <= 0xdbff){
                    uint32_t low;
                    if(slen - i - 1 < 6 || src[i+1] != '\\' || src[i+2] != 'u' ||
                       hex4((const uint8_t *)src + i + 3, 4, &low) ||
                       low < 0xdc00 || low > 0xdfff) return -1;
                    cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00;
                    i += 6;
                }
                int n = utf8(cp, (uint8_t *)dst + j, dlen - j);
                if(n < 0) return -1;
                j += n;
                continue;
            }
            default: return -1;
            }
        } else if(c < 0x20 || c == '"') return -1;
        if(j == dlen) return -1;
        dst[j++] = c;
    }
    return 0;
}

int encode_json_unicode(const uint8_t *src, uint8_t *dst, size_t slen, size_t dlen)
{
    uint32_t cp;
    if(hex4(src, slen, &cp)) return -1;
    return utf8(cp, dst, dlen);
}
