/*
    Copyright 2007 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl.txt
*/



#ifdef __MINGW32__
    #define NTS     "I64"
#else
    #define NTS     "ll"
#endif



#define TYPE_8BIT       1
#define TYPE_16BIT      2
#define TYPE_32BIT      4
#define TYPE_64BIT      8
#define TYPE_FLOAT      16
#define TYPE_DOUBLE     32
#define TYPE_CRC        64
#define TYPE_FORCE_HEX  128
#define TYPE_AND        256
#define TYPE_NOBIG      512



#define ENDIAN_LITTLE   0
#define ENDIAN_BIG      1



enum {
    CMD_TITLE,
    CMD_TYPE,
    CMD_DATA,
    CMD_NONE = -1
};



uint64_t    current_type;
uint8_t     *current_title;



int delimit(uint8_t *data) {
    uint8_t *p;

    for(p = data; *p && (*p != '\n') && (*p != '\r'); p++);
    *p = 0;
    return(p - data);
}



int lowstr(uint8_t *data) {
    uint8_t *p;

    for(p = data; *p; p++) {
        *p = tolower(*p);
    }
    return(p - data);
}



uint64_t get_fmt_char(uint8_t **data) {
    uint64_t    num;
    int         len;
    uint8_t     *str;

    str = *data;
    if(!str || !str[0]) {
        *data = NULL;
        return(0);
    }
    if(str[0] == '\\') {    // \n and so on
        len = 0;
        switch(str[1]) {
            case '\"':  num = '\"';                                 break;
            case '\'':  num = '\'';                                 break;
            case '\\':  num = '\\';                                 break;
            case 'a':   num = '\a';                                 break;
            case 'b':   num = '\b';                                 break;
            case '\f':  num = '\f';                                 break;
            case '\n':  num = '\n';                                 break;
            case '\r':  num = '\r';                                 break;
            case '\t':  num = '\t';                                 break;
            case '\v':  num = '\v';                                 break;
            case 'x':   sscanf(str + 2, "%"NTS"x%n", &num, &len);   break;  // hex
            default:    sscanf(str + 1, "%"NTS"o%n", &num, &len);   break;  // octal
        }
        len += 2;
    } else {
        len = 1;
        num = str[0];       // 'a'
    }

    str += len;
    if(!str[0]) {
        *data = NULL;
    } else {
        *data = str;
    }
    return(num);
}



int check_num_type(uint8_t *data) {
    int         c,
                ret = 0;
    uint8_t     *p;

    for(p = data; (c = *p); p++) {
        if((c >= '0') && (c <= '9')) {
            // ret = 0;
        } else if((c >= 'a') && (c <= 'f')) {
            ret = TYPE_FORCE_HEX;
        } else if(c == '.') {
            ret = TYPE_FLOAT;
            break;
        }
    }
    return(ret);
}



uint64_t get_num(uint8_t *data) {
    float       numf;
    double      numlf;
    int         chk;
    uint64_t    num;
    uint32_t    tmp32;
    uint8_t     *p;

    if(!data || !data[0]) return(0);

    num = 0;
    if(data[0] == '\'') {
        p = data + 1;
        num = get_fmt_char(&p);
    } else {
        lowstr(data);

        if(data[0] == '_') data++;
        chk = check_num_type(data);

        if(!strcmp(data, "int_min")) {                                  // INT_MIN
            num = (uint64_t)0x80000000;
        } else if(!strcmp(data, "int_max")) {                           // INT_MAX
            num = (uint64_t)0x7fffffff;
        } else if(!strcmp(data, "i64_min")) {                           // I64_MIN
            num = (uint64_t)0x8000000000000000ULL;
        } else if(!strcmp(data, "i64_max")) {                           // I64_MAX
            num = (uint64_t)0x7fffffffffffffffULL;
        } else if(current_type & TYPE_DOUBLE) {                         // DOUBLE
//            if(chk != TYPE_FLOAT) printf("- %s\n  a double without dot???\n", current_title);
            numlf = atof(data);
            memcpy(&num, &numlf, sizeof(numlf));
        } else if(strchr(data, '.') || (current_type & TYPE_FLOAT)) {   // FLOAT
//            if(chk != TYPE_FLOAT) printf("- %s\n  a float without dot???\n", current_title);
            numf = atof(data);
            memcpy(&tmp32, &numf, 4);
            num = tmp32;
        } else if(strstr(data, "0x") || strchr(data, '$') || strchr(data, 'h') || (current_type & TYPE_FORCE_HEX)){
            if(chk == TYPE_FLOAT) goto error;                           // HEX
            sscanf(data, "%"NTS"x", &num);
        } else {                                                        // DECIMAL
            if((chk == TYPE_FORCE_HEX) || (chk == TYPE_FLOAT)) goto error;
            sscanf(data, "%"NTS"i", &num);
        }
    }

    return(num);

error:
    printf("\n"
        "Error: %s\n"
        "       the number \"%s\" doesn't match the type specified\n",
        current_title,
        data);
    free_sign();
    exit(1);
}



uint8_t *get_cfg_cmd(uint8_t *line, int *cmdnum) {
    int         i,
                cmdret;
    uint8_t     *cmd,
                *p,
                *l;
    static const uint8_t *command[] = {
                "TITLE",
                "TYPE",
                "DATA",
                NULL };

    cmdret  = CMD_NONE;
    *cmdnum = CMD_NONE;

    l = line + delimit(line);

    for(p = line; *p; p++) {        // clear start
        if((*p != ' ') && (*p != '\t')) break;
    }
    if(!*p) return(NULL);

    cmd = p;                        // cmd

    for(l--; l > p; l--) {          // clear end
        if(*l > ' ') break;
    }
    *(l + 1) = 0;

    if((*cmd == '=') || (*cmd == '#') || (*cmd == '/') || (*cmd == ';')) return(NULL);

    for(p = cmd; *p > ' '; p++);    // find where the command ends

    for(i = 0; command[i]; i++) {
        if(!memcmp(cmd, command[i], p - cmd)) {
            cmdret = i;
            break;
        }
    }

    if(cmdret != CMD_NONE) {        // skip the spaces between the comamnd and the instructions
        for(; *p; p++) {
            if((*p != ' ') && (*p != '\t')) break;
        }
        cmd = p;
    }

    // do not enable this or will not work!
    // if((*cmd == '=') || (*cmd == '#') || (*cmd == '/') || (*cmd == ';')) return("");

    *cmdnum = cmdret;
    return(cmd);
}



    /* here we catch each line (till line feed) */
    /* returns a pointer to the next line       */
uint8_t *get_line(uint8_t *data) {
    uint8_t  *p;

    for(p = data; *p && (*p != '\n') && (*p != '\r'); p++);
    if(!*p) return(NULL);
    *p = 0;
    for(p++; *p && ((*p == '\n') || (*p == '\r')); p++);
    if(!*p) return(NULL);
    return(p);
}



    /* here we catch each element of the line */
    /* returns a pointer to the next element  */
uint8_t *get_element(uint8_t **data, int *isastring) {
    uint8_t  *p;

    p = *data;

    if((p[0] == '/') && (p[1] == '*')) {    // /* comment */
        for(p += 2; *p; p++) {
            if((p[0] == '*') && (p[1] == '/')) {
                p += 2;
                break;
            }
        }
    } else if(*p == '"') {                  // string
        if(isastring) *isastring = 1;
        p++;
        for(*data = p; *p && (*p != '\"'); p++) {
            if(*p == '\\') p++;
            if(!*p) break;
        }
    } else {
        if(isastring) *isastring = 0;
        while(*p && (*p != '\t') && (*p != ' ') && (*p != ',') && (*p != '{') && (*p != '}') && (*p != '(') && (*p != ')')) p++;
    }

    if(!*p) return(NULL);                   // end of line
    *p = 0;

    for(p++; *p && ((*p == '\t') || (*p == ' ')); p++);
    if(!*p) return(NULL);                   // start of next line
    return(p);
}



void cfg_title(uint8_t *line) {
    if(current_title) free(current_title);
    current_title = strdup(line);
}



void cfg_type(uint8_t *line) {
    uint8_t     *next,
                *sc,
                *scn;

    current_type = 0;

    next = NULL;
    do {
        next = get_line(line);

        sc  = line;
        scn = NULL;
        do {
            scn = get_element(&sc, NULL);

            if((sc[0] == '#') || (sc[0] == '/') || (sc[0] == ';')) break; // comments

            lowstr(sc);

#define C(X)    !strcmp(sc, X)
#define S(X)    strstr(sc, X)
            if(C("unsigned")) continue;
            if(!memcmp(sc, "u_", 2)) sc += 2;
            if(sc[0] == 'u') sc++;

            if(S("int8")  || C("8")  || S("char"))              current_type |= TYPE_8BIT;
            if(S("int16") || C("16") || S("short"))             current_type |= TYPE_16BIT;
            if(S("int32") || C("32") || C("int") || S("long"))  current_type |= TYPE_32BIT;
            if(S("int64") || C("64"))                           current_type |= TYPE_64BIT;
            if(C("float"))                                      current_type |= TYPE_FLOAT;
            if(C("double"))                                     current_type |= TYPE_DOUBLE;
            if(C("crc")   || C("checksum"))                     current_type |= TYPE_CRC;
            if(C("hex")   || C("forcehex"))                     current_type |= TYPE_FORCE_HEX;
            if(C("and")   || C("&&"))                           current_type |= TYPE_AND;
            if(C("nobig"))                                      current_type |= TYPE_NOBIG;
#undef C
#undef S

            sc = scn;
        } while(scn);

        line = next;
    } while(next);
}



uint8_t *cfg_add_element(uint8_t *op, int *oplen, uint64_t num, int size, int endian) {
    int     len = *oplen;

    if((size == 8) && (endian == ENDIAN_BIG)) return(op);

    if((int64_t)num >= 0) {
        if((size == 8)  && (num > 0xff))        goto error;
        if((size == 16) && (num > 0xffff))      goto error;
        if((size == 32) && (num > 0xffffffff))  goto error;
    }

    len += size >> 3;
    op = realloc(op, len);
    if(!op) std_err();

    if(size == 8) {
        op[len - 1] = num;

    } else if(size == 16) {
        if(endian == ENDIAN_LITTLE) {
            op[len - 2] = (num      );
            op[len - 1] = (num >>  8);
        } else {
            op[len - 2] = (num >>  8);
            op[len - 1] = (num      );
        }

    } else if(size == 32) {
        if(endian == ENDIAN_LITTLE) {
            op[len - 4] = (num      );
            op[len - 3] = (num >>  8);
            op[len - 2] = (num >> 16);
            op[len - 1] = (num >> 24);
        } else {
            op[len - 4] = (num >> 24);
            op[len - 3] = (num >> 16);
            op[len - 2] = (num >>  8);
            op[len - 1] = (num      );
        }

    } else if(size == 64) {
        if(endian == ENDIAN_LITTLE) {
            op[len - 8] = (num      );
            op[len - 7] = (num >>  8);
            op[len - 6] = (num >> 16);
            op[len - 5] = (num >> 24);
            op[len - 4] = (num >> 32);
            op[len - 3] = (num >> 40);
            op[len - 2] = (num >> 48);
            op[len - 1] = (num >> 56);
        } else {
            op[len - 8] = (num >> 56);
            op[len - 7] = (num >> 48);
            op[len - 6] = (num >> 40);
            op[len - 5] = (num >> 32);
            op[len - 4] = (num >> 24);
            op[len - 3] = (num >> 16);
            op[len - 2] = (num >>  8);
            op[len - 1] = (num      );
        }
    }

    *oplen = len;
    return(op);

error:
    printf("\n"
        "Error: %u) %s\n"
        "       the number 0x%"NTS"x is bigger than %d bits\n"
        "       check your signature file, probably you must increate the TYPE size\n",
        signs, current_title,
        num, size);
    free_sign();
    exit(1);
}    



void add_sign(uint8_t *type, uint8_t *endian, uint8_t *data, int datasize, int bits) {
    int     len;

    if(!datasize) return;
    if(!*type) endian = "";
    sign = realloc(sign, sizeof(sign_t *) * (signs + 1));
    if(!sign) std_err();
    sign[signs]        = malloc(sizeof(sign_t));
    if(!sign[signs]) std_err();
    sign[signs]->title = malloc(strlen(current_title) + strlen(type) + strlen(endian) + 10 + 5 + 1);
    len = sprintf(sign[signs]->title, "%s [%s.%s.%u%s]",
        current_title, type, endian, datasize, (current_type & TYPE_AND) ? "&" : "");
    sign[signs]->data  = data;
    sign[signs]->size  = datasize;
    sign[signs]->and   = 0;
    if(current_type & TYPE_AND) sign[signs]->and = bits;

    sign_alloclen = sign_alloclen
        + sizeof(sign_t *)
        + sizeof(sign_t)
        + len
        + datasize;
    signs++;
}



#define BITMASK(SIZE)   ((uint64_t)1 << (SIZE))



uint64_t reflect(uint64_t v, int b) {
    uint64_t    t;
    int         i;

    t = v;
    for(i = 0; i < b; i++) {
        if(t & (uint64_t)1) {
            v |= BITMASK((b - 1) - i);
        } else {
            v &= ~BITMASK((b - 1) - i);
        }
        t >>= 1;
    }
    return(v);
}



uint64_t widmask(int size) {
    return((((uint64_t)1 << (size - 1)) - (uint64_t)1) << (uint64_t)1) | (uint64_t)1;
}



uint64_t cm_tab(int inbyte, uint64_t poly, int size, int rever) {
    uint64_t    r,
                topbit;
    int         i;

    topbit = BITMASK(size - 1);

    if(rever) inbyte = reflect(inbyte, 8);

    r = inbyte << (size - 8);

    for(i = 0; i < 8; i++) {
        if(r & topbit) {
            r = (r << 1) ^ poly;
        } else {
            r <<= 1;
        }
    }

    if(rever) r = reflect(r, size);

    return(r & widmask(size));
}



uint8_t *make_crc(uint8_t *op, int *oplen, uint64_t poly, int size, int endian, int rever) {
    uint64_t    num;
    int         i,
                len = *oplen;

    for(i = 0; i < 256; i++) {
        num = cm_tab(i, poly, size, rever);
        op = cfg_add_element(op, &len, num, size, endian);
    }

    *oplen = len;
    return(op);
}



void cfg_data(uint8_t *line) {
    int         opi8len   = 0,
                opi16len  = 0,
                opi32len  = 0,
                opi64len  = 0,
                opifltlen = 0,
                opidbllen = 0;
    uint8_t     *opi8     = NULL,
                *opi16    = NULL,
                *opi32    = NULL,
                *opi64    = NULL,
                *opiflt   = NULL,
                *opidbl   = NULL;

    int         opb8len   = 0,
                opb16len  = 0,
                opb32len  = 0,
                opb64len  = 0,
                opbfltlen = 0,
                opbdbllen = 0;
    uint8_t     *opb8     = NULL,   // NEVER used
                *opb16    = NULL,
                *opb32    = NULL,
                *opb64    = NULL,
                *opbflt   = NULL,
                *opbdbl   = NULL;

    int         opicrclen = 0,
                opbcrclen = 0;
    uint8_t     *opicrc   = NULL,
                *opbcrc   = NULL;

    int         opstrlen  = 0;
    uint8_t     *opstr    = NULL;

    uint64_t    num;
    int         isastring = 0;
    uint8_t     *next,
                *sc,
                *scn,
                *p;

    if(!current_type) current_type |= TYPE_8BIT;

    next = NULL;
    do {
        next = get_line(line);

        sc  = line;
        scn = NULL;
        do {
            scn = get_element(&sc, &isastring);

            if((sc[0] == '/') && (sc[1] == '*')) goto scn_continue;
            if((sc[0] == '#') || (sc[0] == '/') || (sc[0] == ';')) break; // comments
            if(!sc[0]) goto scn_continue;

            if(isastring) {
                for(p = sc; p;) {
                    num = get_fmt_char(&p);
                    opstr = cfg_add_element(opstr, &opstrlen, num, 8, ENDIAN_LITTLE);
                }
                goto scn_continue;
            }

            num = get_num(sc);

            if(current_type & TYPE_CRC) {
                    /* ONLY ONE CRC AT TIME IS ALLOWED */

#define DOIT(TYPENAME, BITS, TYPE)  \
                if(current_type & TYPE_##TYPENAME) {                                        \
                    opicrc = make_crc(NULL, &opicrclen, num, BITS, ENDIAN_LITTLE, 1);       \
                    add_sign(TYPE, "le rev", opicrc, opicrclen, BITS);                      \
                    if((num != 1) && (current_type & TYPE_NOBIG)) {                         \
                        opicrclen = 0;                                                      \
                        opicrc = make_crc(NULL, &opicrclen, num, BITS, ENDIAN_LITTLE, 0);   \
                        add_sign(TYPE, "le", opicrc, opicrclen, BITS);                      \
                    }                                                                       \
                    if(BITS > 8) {                                                          \
                        opbcrc = make_crc(NULL, &opbcrclen, num, BITS, ENDIAN_BIG, 1);      \
                        add_sign(TYPE, "be rev", opbcrc, opbcrclen, BITS);                  \
                        if(current_type & TYPE_NOBIG) {                                     \
                            opbcrclen = 0;                                                  \
                            opbcrc = make_crc(NULL, &opbcrclen, num, BITS, ENDIAN_BIG, 0);  \
                            add_sign(TYPE, "be", opbcrc, opbcrclen, BITS);                  \
                        }                                                                   \
                    }                                                                       \
                }

                DOIT(8BIT,   8,   "")
                DOIT(16BIT,  16,  "16")
                DOIT(32BIT,  32,  "32")
                DOIT(64BIT,  64,  "64")

#undef DOIT

                return;
            }

#define DOIT(TYPENAME, NAME, BITS)  \
            if(current_type & TYPE_##TYPENAME) {  \
                opi##NAME = cfg_add_element(opi##NAME, &opi##NAME##len, num, BITS, ENDIAN_LITTLE);  \
                opb##NAME = cfg_add_element(opb##NAME, &opb##NAME##len, num, BITS, ENDIAN_BIG);     \
            }

            DOIT(8BIT,   8,   8)
            DOIT(16BIT,  16,  16)
            DOIT(32BIT,  32,  32)
            DOIT(64BIT,  64,  64)
            DOIT(FLOAT,  flt, 32)

                /* stupid and lame work-around for double and float */
                /* but it works 8-) */
            if(current_type & TYPE_FLOAT) {     // if float = do double too
                current_type |= TYPE_DOUBLE;    // enable double
                num = get_num(sc);              // re-read the number
                DOIT(DOUBLE, dbl, 64)           // add it
                current_type ^= TYPE_DOUBLE;    // disable double
            }

#undef DOIT

scn_continue:
            sc = scn;
        } while(scn);

        line = next;
    } while(next);

#define DOIT(NAME, BITS, TYPE)    \
    if(opi##NAME) add_sign(TYPE, "le", opi##NAME, opi##NAME##len, BITS);    \
    if(current_type & TYPE_NOBIG) {                                         \
        free(opb##NAME);                                                    \
        opb##NAME = NULL;                                                   \
    }                                                                       \
    if(opb##NAME) {                                                         \
        if(opi##NAME) { /* remove duplicates! */                            \
            if(!memcmp(opi##NAME, opb##NAME, opb##NAME##len)) {             \
                free(opb##NAME);                                            \
            } else {                                                        \
                add_sign(TYPE, "be", opb##NAME, opb##NAME##len, BITS);      \
            }                                                               \
        }                                                                   \
    }

    DOIT(8,     8,      "")
    DOIT(16,    16,     "16")
    DOIT(32,    32,     "32")
    DOIT(64,    64,     "64")
    DOIT(flt,   32,     "float")
    DOIT(dbl,   64,     "double") 
    if(opstr) add_sign("", "", opstr, opstrlen, 8);

#undef DOIT
}



void cfg_cmd(int cmdnum, uint8_t *line) {
    switch(cmdnum) {
        case CMD_TITLE: cfg_title(line);    break;
        case CMD_TYPE:  cfg_type(line);     break;
        case CMD_DATA:  cfg_data(line);     break;
        default:                            break;
    }
}



void read_cfg(uint8_t *filename) {
    FILE    *fd;
    int     len,
            currlen,
            bufflen,
            oldnum,
            cmdnum,
            tmp;
    uint8_t line[256],
            *buff,
            *buff_limit,
            *data,
            *ins;

    printf("- open file %s\n", filename);
    fd = fopen(filename, "rb");
    if(!fd) std_err();

    bufflen    = 256;
    buff       = malloc(bufflen);
    if(!buff) std_err();
    data       = buff;
    buff_limit = buff + bufflen;
    buff[0]    = 0;
    line[0]    = 0;
    oldnum     = CMD_NONE;

    while(fgets(line, sizeof(line), fd)) {
        ins = get_cfg_cmd(line, &cmdnum);
        if(!ins) continue;

        if(oldnum == CMD_NONE) oldnum = cmdnum;
        if(cmdnum == CMD_NONE) cmdnum = oldnum;
        if(cmdnum != oldnum) {
            tmp    = cmdnum;
            cmdnum = oldnum;
            oldnum = tmp;

            cfg_cmd(cmdnum, buff);

            data = buff;
        }

        len = strlen(ins);  // allocation
        if((data + len) >= buff_limit) {
            currlen    = data - buff;
            bufflen    = currlen + 1 + len + 1; // 1 for \n and 1 for the final NULL byte
            buff       = realloc(buff, bufflen);
            if(!buff) std_err();
            data       = buff + currlen;
            buff_limit = buff + bufflen;
        }

        if(data > buff) data += sprintf(data, "\n");
        data += sprintf(data, "%s", ins);
        line[0] = 0;
    }
        // the remaining line
    cmdnum = oldnum;
    if((cmdnum != CMD_NONE) && (data != buff)) cfg_cmd(cmdnum, buff);

    free(buff);
    fclose(fd);
}
