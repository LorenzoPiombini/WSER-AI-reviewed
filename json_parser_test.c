#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include "json.h"

int main()
{
	struct {
		const char *input;       // four chars after \u
		uint8_t expected[4];
		int expected_len;
	} tests[] = {
		// 1-byte UTF-8
		{ "0000", {0x00},                   1 },
		{ "0041", {0x41},                   1 }, // A
		{ "007F", {0x7F},                   1 },

		// 2-byte UTF-8
		{ "0080", {0xC2, 0x80},             2 },
		{ "00E9", {0xC3, 0xA9},             2 }, // é
		{ "07FF", {0xDF, 0xBF},             2 },

		// 3-byte UTF-8
		{ "0800", {0xE0, 0xA0, 0x80},       3 },
		{ "20AC", {0xE2, 0x82, 0xAC},       3 }, // €
		{ "4E2D", {0xE4, 0xB8, 0xAD},       3 }, // 中

		// Right before surrogate range
		{ "D7FF", {0xED, 0x9F, 0xBF},       3 },

		// Surrogates -- should currently reject
		{ "D800", {0},                     -1 },
		{ "DFFF", {0},                     -1 },

		// Right after surrogate range
		{ "E000", {0xEE, 0x80, 0x80},       3 },

		// Largest non-surrogate representable by one \uXXXX
		{ "FFFF", {0xEF, 0xBF, 0xBF},       3 },
	};
	char *jsons[]= {"{\n\t\"name\": \"Jane Doe\",\n\t\"age\": 28,\n\t\"city\": \"Los Angeles\",\n\t\"isEmployed\": true,\n\t\"skills\": [\"Python\",\n\t\"JSON\",\n\t\"Data Analysis\"],\n\t\"projects\":\n\t\t{\n\t\t\t\"count\": 3,\n\t\t\t\"active\": \"Database Migration\"\n\t\t}\n}",
		"{\"a\":1","{\"a\":1]",
		"{\"a\":\"unterminated",
		"{\"a\":\"bad\\x\"}",
		"{\"a\":tru}",
		"{\"a\":1.}",
		"{\"a\":.5}",
		"{\"a\":01}",
		"{\"a\":+1}",
		"{\"a\":\"\t\"}",
		"}",
		"{}",
		"{\"a\":\"say \\\"hi\\\"\"}",
		"{\"a\":\"\\u0041\"}",
		"{\"a\":-2.2,\"b\":1e-3,\"c\":1E+10}",
		"{(\"a\":[[[]]])}",
		"{\"a\":[[[]]]}",
		"{{\"a\":null}}",
		"{\"a\":true}",
		"{,\"a\":false}",
		"{\"a\":false,}",
		"{\"a\":[]}",
		"{\"a\":\"c:\\\\path\"}",
		"{\"a\":\"\\b\\f\\n\\r\\t\\/\"}",
		"{\"name\":\"Smith & Sons: Wholesale\"}",
		"{\"a\":\"caff\xc3\xa8\"}",
		"[[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]]",
		"{\"a\" 1}",
		"{\"a\":1 \"b\":2}",
		"{\"a\"::1}",
		"{\"a\":[1,]}",
		"{\"a\":[,1]}",
		"{}{}",
		"{}true",
		"{\"a\":null}",
		"{\"outer\":{\"a\":null}}",
		"{\"a\":[[[]]]}",
		"{\"a\":\"\"}",
		NULL};

	const int expected[] = {
		0, /*  1: Jane Doe object */
		-1, /*  2: missing closing brace */
		-1, /*  3: mismatched closing bracket */
		-1, /*  4: unterminated string */
		-1, /*  5: invalid escape */
		-1, /*  6: incomplete literal */
		-1, /*  7: number 1. */
		-1, /*  8: number .5 */
		-1, /*  9: leading zero */
		-1, /* 10: leading plus */
		-1, /* 11: string containing ordinary spaces */
		-1, /* 12: lone closing brace */
		0, /* 13: empty object */
		0, /* 14: escaped quotes */
		0, /* 15: Unicode escape */
		0, /* 16: decimal and exponents */
		-1, /* 17: parentheses inside object */
		0, /* 18: nested empty arrays */
		-1, /* 19: unnamed nested object */
		0, /* 20: true */
		-1, /* 21: leading comma */
		-1, /* 22: trailing comma */
		0, /* 23: empty array value */
		0, /* 24: escaped backslash */
		0, /* 25: valid escape sequences */
		0, /* 26: punctuation inside string */
		0, /* 27: UTF-8 string */
		-3, /* 28: depth limit exceeded */
		-1, /* 29: missing colon */
		-1, /* 30: missing comma */
		-1, /* 31: double colon */
		-1, /* 32: trailing comma in array */
		-1, /* 33: leading comma in array */
		-1, /* 34: multiple root objects */
		-1, /* 35: literal after root object */
		0, /* 36: null value */
		0, /* 37: named nested object */
		0, /* 38: nested empty arrays */
		0  /* 39: empty string */
	};

	int i = 0;
	while(jsons[i] != NULL){
		struct Json_token tok[JSON_MAX_TOKENS] = {0};

		int res = json_parser(jsons[i],strlen(jsons[i]),tok,JSON_MAX_TOKENS);
		if(res > 0){
			assert(expected[i] == 0);
			i++;
			continue;
		}
		if(res != expected[i]) printf("%d\n",i);
		assert(res == expected[i]);
		i++;
	}
	printf("all json tests passed\n");
	
	for(size_t j = 0; j < sizeof(tests) / sizeof(tests[0]); j++){
		uint8_t dst[4] = {0}; 
		int r = encode_json_unicode((const uint8_t *)tests[j].input,dst,4,sizeof(dst));
		assert(r == tests[j].expected_len);

		if(r == -1) {
			printf("PASS \\u%s: rejected surrogate\n",tests[j].input);
			continue;
		}

		assert(memcmp(dst,tests[j].expected,tests[j].expected_len) == 0);

		printf("PASS \\u%s\n",tests[j].input);
	}
	
	return 0;
}
