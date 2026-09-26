
#ifndef _JSON_H_
#define _JSON_H_ 1

#include <stddef.h>
#include <stdint.h>

#define JSON_MAX_DEPTH 20
#define JSON_MAX_TOKENS 512
#define JSON_END_ARRAY (0 | 0x02000000)

/*Mini Json parser def*/
/*json grammar*/
enum json_type{
	OBJECT_JS,
	ARRAY_JS,
	STRING_JS,
	NUMBER_JS,
	TRUE_JS,
	FALSE_JS,
	NUL_JS
};

enum json_state{
	KEY,
	VALUE,
	COLON,
	COMMA_OR_CLOSING_OBJ,
	END,
	VALUE_OR_CLOSING_OBJECT,
	KEY_OR_CLOSING_OBJECT
};

enum sturctural_chars{
	BEGIN_ARRAY = 		(int) '[',
	END_ARRAY = 		(int) ']',
	BEGIN_OBJECT = 		(int) '{',
	END_OBJECT = 		(int) '}',
	NAME_SEPARATOR = 	(int) ':',
	VALUE_SEPARATOR = 	(int) ','
};

enum ws{
	SPACE = 			(int) ' ',
	H_TAB = 			(int) '\t',
	NEW_LINE = 			(int) '\n',
	CARRIAGE_RETURN = 	(int) '\r'
};


enum json_error{
	JSON_INVALID_ERR = -1,
	JSON_TK_LIMIT_ERR = -2,
	JSON_DEPTH_LIMIT_ERR = -3
};

struct Json_token{
	int type;
	int start;
	int end;
	int size;/*children*/
	int parent;
};


int json_parser(const char *json, size_t len,struct Json_token *tokens, size_t max_tokens);
/* Decode unquoted string contents to raw bytes; no terminator is appended. */
int decode_json_escape(const char *src, size_t slen, char *dst, size_t dlen);
int encode_json_unicode(const uint8_t *src, uint8_t *dst,size_t slen,size_t dlen);
int write_actual_json_tokens_to_mem(char *buf,size_t buf_size, struct Json_token *t,size_t token_size);
int is_token_empty(struct Json_token *t);
#endif
