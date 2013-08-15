/*     
 * Light_Email_Filter
 * Copyright (c) 2013, Ilmar 'SeaEagle1' Kruis <seaeagle1@users.sourceforge.net>
 * 
 *     This Source Code Form is subject to the
 *     terms of the Mozilla Public License, v.
 *     2.0. If a copy of the MPL was not
 *     distributed with this file, You can
 *     obtain one at
 *     http://mozilla.org/MPL/2.0/.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/wait.h>

#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include "usuals.h"

#include "compat.h"
#include "sock_any.h"
#include "stringx.h"
#include "smtppass.h"

#include <dkim.h>
#include <spf2/spf.h>

/* -----------------------------------------------------------------------
 *  FORWARD DECLARATIONS
 */

static void usage();
static void final_reject_message(char* buf, int buflen);
static void buffer_reject_message(char* data, char* buf, int buflen);
static int verify_data(spctx_t *ctx);
static int sign_data(spctx_t *ctx);

#define DEFAULT_CONFIG      CONF_PREFIX "/lefilter.conf"
#define DEFAULT_TIMEOUT     30

/* ----------------------------------------------------------------------------------
 *  STARTUP ETC...
 */

#ifndef HAVE___ARGV
char** __argv;
#endif

#define MODE_SIGN 1
#define MODE_VERIFY 0

static int mode = 0;

/* libdkim */
static DKIMSignOptions dkim_opts = {0};
static char keyBuffer[3000];
static int key_is_set = 0;
static char *keyfile;

/* libspf2 */
static SPF_server_t *spf_server = NULL;

int main(int argc, char* argv[])
{
    const char* configfile = DEFAULT_CONFIG;
    const char* pidfile = NULL;
    int dbg_level = -1;
    int ch = 0;
    int r;
    char* t;

#ifndef HAVE___ARGV
    __argv = argv;
#endif

    /* Setup some defaults */
    sp_init("light_email_filter");

    /*
     * We still accept our old arguments for compatibility reasons.
     * We fill them into the spstate structure directly
     */

    /* Parse the arguments nicely */
    while((ch = getopt(argc, argv, "d:f:p:v")) != -1)
    {
        switch(ch)
        {
		/*  Don't daemonize  */
        case 'd':
            dbg_level = strtol(optarg, &t, 10);
            if(*t) /* parse error */
                errx(1, "invalid debug log level");
            dbg_level += LOG_ERR;
            break;

        /* The configuration file */
        case 'f':
            configfile = optarg;
            break;

        /* Write out a pid file */
        case 'p':
            pidfile = optarg;
            break;

        /* Print version number */
        case 'v':
            printf("light_email_filter (version %s)\n", VERSION);
            printf("                   (config: %s)\n", DEFAULT_CONFIG);
            exit(0);
            break;

        /* Usage information */
        case '?':
        default:
            usage();
            break;
		}
    }

	argc -= optind;
	argv += optind;

    if(argc > 0)
        usage();

    r = sp_run(configfile, pidfile, dbg_level);

    sp_done();
    
    if(spf_server != NULL)
        SPF_server_free(spf_server);

    return r;
}

static void usage()
{
    fprintf(stderr, "usage: light_email_filter [-d debuglevel] [-f configfile] [-p pidfile]\n");
    fprintf(stderr, "       light_email_filter -v\n");
    exit(2);
}

/* ----------------------------------------------------------------------------------
 *  SP CALLBACKS
 */
int cb_check_pre(spctx_t* ctx)
{
    return 1;
}

int cb_check_data(spctx_t* ctx)
{
    if(mode == MODE_VERIFY)
	return verify_data(ctx);
    else if(mode == MODE_SIGN)
	return sign_data(ctx);
    else
        return -1;
}

int cb_parse_option(const char* name, const char* value)
{
    if(strcasecmp("Mode", name) == 0)
    {
        if(strcasecmp("sign", value) == 0)
	    mode = MODE_SIGN;
	else if(strcasecmp("verify", value) == 0)
	    mode = MODE_VERIFY;
	else
	    sp_messagex(NULL, LOG_ERR, "Unknown Mode setting");
	
	return 1;
    }
    
    if(strcasecmp("Selector", name) == 0)
    {
        strncpy(dkim_opts.szSelector, value, sizeof(dkim_opts.szSelector));
	return 1;
    }
    
    if(strcasecmp("Domain", name) == 0)
    {
        strncpy(dkim_opts.szDomain, value, sizeof(dkim_opts.szDomain));
	return 1;
    }    
    
    if(strcasecmp("PrivateKey", name) == 0)
    {
        keyfile = value;
	return 1;
    }
    
    if(strcasecmp("Expiry", name) == 0)
    {
	time_t t;
	time(&t);
	char *pEnd;
	dkim_opts.expireTime = t + strtol(value, &pEnd, 10);   
	return 1;
    }
    
    return 0;
}

spctx_t* cb_new_context()
{
    spctx_t* ctx = (spctx_t*)calloc(1, sizeof(spctx_t));
    if(!ctx)
        sp_messagex(NULL, LOG_CRIT, "out of memory");
    return ctx;
}

void cb_del_context(spctx_t* ctx)
{
    free(ctx);
}

/* -----------------------------------------------------------------------------
 * IMPLEMENTATION
 */

static int verify_data(spctx_t* ctx)
{
    char ebuf[256];
    int n;
    SPF_request_t *spf_request = NULL;
    char * xforwardaddr = NULL;
    char * xforwardhelo = NULL;
    
    if(spf_server == NULL)
    {
	/* redirect errors */
	SPF_error_handler = SPF_error_syslog; 
	SPF_warning_handler = SPF_warning_syslog; 
	SPF_info_handler = SPF_info_syslog; 
	SPF_debug_handler = SPF_debug_syslog;
      
        spf_server = SPF_server_new(SPF_DNS_CACHE, 1);
	if (spf_server == NULL) 
	    return -1;	  
    }
    
    /* trim string */
    if(ctx->xforwardaddr)
	xforwardaddr = trim_space(ctx->xforwardaddr);
    if(ctx->xforwardhelo)
	xforwardhelo = trim_space(ctx->xforwardhelo);
    
    sp_messagex(ctx, LOG_DEBUG, "New connection: ADDR %s - MAIL FROM %s - XF-ADDR %s - XF-HELO %s", 
		ctx->client.peername, ctx->sender, xforwardaddr, xforwardhelo);
    
    spf_request = SPF_request_new(spf_server);
    if( xforwardaddr )
      SPF_request_set_ipv4_str( spf_request, xforwardaddr );
    else if ( ctx->client.peername )
      SPF_request_set_ipv4_str( spf_request, ctx->client.peername );
    if( xforwardhelo )
      SPF_request_set_helo_dom( spf_request, xforwardhelo );
    if( ctx->sender )
      SPF_request_set_env_from( spf_request, ctx->sender );

    SPF_response_t *spf_response = NULL;
    SPF_request_query_mailfrom(spf_request, &spf_response);
    
    char hostname[100];
    strncpy(hostname, SPF_request_get_rec_dom(spf_request), 99);
    
    char *result_spf = NULL;
    switch(SPF_response_result(spf_response))
    {     
      case SPF_RESULT_NONE: 	
	sp_messagex(ctx, LOG_DEBUG, "No SPF policy found for %s", ctx->sender); 
	result_spf = "none";
	break;
	
      case SPF_RESULT_NEUTRAL: 
        result_spf = "neutral";
	sp_messagex(ctx, LOG_DEBUG, "SPF: NEUTRAL for %s", ctx->sender); 
	break;

      case SPF_RESULT_SOFTFAIL:
	result_spf = "softfail";
	sp_messagex(ctx, LOG_DEBUG, "SPF: SOFTFAIL for %s", ctx->sender); 
	break;
	
      case SPF_RESULT_PASS:
	result_spf = "pass";
	sp_messagex(ctx, LOG_DEBUG, "SPF: PASS for %s", ctx->sender); 
        break;
	
      case SPF_RESULT_FAIL:
	buffer_reject_message("550 SPF Reject", ebuf, sizeof(ebuf));
        buffer_reject_message(SPF_response_get_smtp_comment(spf_response), ebuf, sizeof(ebuf));
        final_reject_message(ebuf, sizeof(ebuf));
	sp_messagex(ctx, LOG_DEBUG, "SPF FAIL for %s, ignore message", ctx->sender); 

	SPF_response_free(spf_response);
	SPF_request_free(spf_request);

	if(sp_fail_data(ctx, ebuf) == -1)
            return -1;	
	else
	    return 0;
	break;
      
      case SPF_RESULT_TEMPERROR:
      case SPF_RESULT_PERMERROR:
      case SPF_RESULT_INVALID:
	buffer_reject_message("450 temporary failure", ebuf, sizeof(ebuf));
        final_reject_message(ebuf, sizeof(ebuf));
	sp_messagex(ctx, LOG_DEBUG, "TEMP ERROR or INVALID RECORD in SPF for %s", ctx->sender); 
 
	SPF_response_free(spf_response);
	SPF_request_free(spf_request);

        if(sp_fail_data(ctx, ebuf) == -1)
            return -1;	
	else
	    return 0;
	break;
    };
    char auth_result_spf[1025];
    snprintf(auth_result_spf, 1024, "spf=%s smtp.mailfrom=%s", result_spf, ctx->sender);
   
    SPF_response_free(spf_response);
    SPF_request_free(spf_request);
    
    
    
    /* Tell client to start sending data */
    if(sp_start_data (ctx) < 0)
        return -1; /* Message already printed */

    /* Setup DKIM verifier */
    DKIMContext ctxt;
    DKIMVerifyOptions vopts = {0};
    vopts.nCheckPractices = 1;
    vopts.pfnSelectorCallback = NULL; //SelectorCallback;

    n = DKIMVerifyInit( &ctxt, &vopts );

    /* Read data into verifier */
    int len = -1;
    const char *buffer = 0;
    do
    {
        len = sp_read_data(ctx, &buffer);
        if(len == -1)
            return -1;
        if(len > 0)
        {
            DKIMVerifyProcess( &ctxt, buffer, len );
	    sp_write_data( ctx, buffer, len );
        }

    } while(len > 0);
    sp_write_data( ctx, NULL, 0 );

    /* Verify DKIM */
    n = DKIMVerifyResults( &ctxt );
    
    /* Get verification details */
    int nSigCount = 0;
    DKIMVerifyDetails* pDetails;
    char szPolicy[512];

    DKIMVerifyGetDetails(&ctxt, &nSigCount, &pDetails, szPolicy );

    /* Proxy based on verification results */
    char auth_result_dkim[1025];
    if(nSigCount == 0)
    {
        sp_messagex(ctx, LOG_DEBUG, "No DKIM signature, passthrough");
	snprintf(auth_result_dkim, 1024, "dkim=none");
    }
    else if (n == DKIM_SUCCESS || n == DKIM_PARTIAL_SUCCESS)
    {
        sp_messagex(ctx, LOG_DEBUG, "DKIM verification: Success, adding header information");
	
	int strpos = 0;
	int i=0;
	for(; i<nSigCount; ++i)
	{
	    snprintf(&auth_result_dkim[strpos], 1024 - strpos, 
		     "%sdkim=%s header.d=%s", (i>0 ? ";\n" : ""),
		     (pDetails[i].nResult == DKIM_SUCCESS ? "pass" : "fail"),
		     pDetails[i].szSignatureDomain);
	    strpos = strlen(auth_result_dkim);
	}
	
    } else {
        sp_messagex(ctx, LOG_DEBUG, "DKIM verification: Failed, report error and ignore message.");

        buffer_reject_message("550 DKIM Signature failed verification (http://www.dkim.org/info/dkim-faq.html)", ebuf, sizeof(ebuf));
        final_reject_message(ebuf, sizeof(ebuf));

        DKIMVerifyFree( &ctxt );

        if(sp_fail_data(ctx, ebuf) == -1)
            return -1;
	else
	    return 0;
    }
    DKIMVerifyFree( &ctxt );

    char auth_results_header[1025];
    snprintf(auth_results_header, 1024, "Authentication-Results: %s;\n %s;\n %s;", 
	     hostname, auth_result_spf, auth_result_dkim);
    
    if( sp_done_data(ctx, auth_results_header) == -1)
        return -1;

    return 0;  
}

static int sign_data(spctx_t *ctx)
{
    char ebuf[256];
    int n;
    DKIMContext ctxt;
    
    strncpy(dkim_opts.szRequiredHeaders, "From;To;Cc;Subject;Date;", 25);
    dkim_opts.nHash = DKIM_HASH_SHA256;
    dkim_opts.nIncludeBodyHash = DKIM_BODYHASH_IETF_1;
    dkim_opts.nCanon = DKIM_SIGN_RELAXED;
    
    if(key_is_set == 0)
    {
	FILE* keyFP = fopen( keyfile, "r" );
	if ( keyFP == NULL ) 
	{
	    sp_messagex(ctx, LOG_ERR, "Unable to open DKIM key file: %s", keyfile);
	    return -1;
	}
	n = fread( keyBuffer, 1, sizeof(keyBuffer), keyFP );
	if (n == sizeof(keyBuffer))  /* TC9 */
	{
	    sp_messagex(ctx, LOG_ERR, "DKIM key is too large, maximum size is %i", sizeof(keyBuffer));
	}
	keyBuffer[n] = '\0';
	fclose(keyFP);
	
	sp_messagex(ctx, LOG_DEBUG, "DKIM key read from %s", keyfile);
	key_is_set = 1;
    }
    
    /* Tell client to start sending data */
    if(sp_start_data (ctx) < 0)
        return -1; /* Message already printed */
        
    n = DKIMSignInit( &ctxt, &dkim_opts );
    sp_messagex(ctx, LOG_DEBUG, "DKIM signer initialised");      

    int len = -1;
    const char *buffer = 0;
    do
    {
        len = sp_read_data(ctx, &buffer);
        if(len == -1)
	{
            DKIMSignFree(&ctxt);
	    return -1;
	}
        if(len > 0)
        {
            DKIMSignProcess( &ctxt, buffer, len );
	    sp_write_data( ctx, buffer, len );
        }

    } while(len > 0);
    sp_write_data( ctx, NULL, 0 );
    
    char *dkim_signature = NULL;
    n = DKIMSignGetSig2( &ctxt, keyBuffer, &dkim_signature );
    sp_messagex(ctx, LOG_DEBUG, "Signing message");
    
    if( sp_done_data(ctx, dkim_signature) == -1 )
    {
	DKIMSignFree(&ctxt);
	return -1;
    } else {
	DKIMSignFree(&ctxt);
	return 0;
    }
}

static void kill_myself()
{
    while (1) {
        kill(getpid(), SIGKILL);
        sleep(1);
    }
}

static void final_reject_message(char* buf, int buflen)
{
    if(buf[0] == 0)
        strlcpy(buf, "530 Content Rejected", buflen);
    else
        trim_end(buf);
}

static void buffer_reject_message(char* data, char* buf, int buflen)
{
    int len = strlen(data);
    char* t = data + len;
    int newline = 0;

    while(t > data && isspace(*(t - 1)))
    {
        t--;

        if(*t == '\n')
            newline = 1;
    }

    /* No valid line */
    if(t > data)
    {
        if(newline)
            *t = 0;

        t = strrchr(data, '\n');
        if(t == NULL)
        {
            t = trim_start(data);

            /*
             * Basically if we already have a newline at the end
             * then we need to start a new line
             */
			if(buf[strlen(buf) - 1] == '\n')
                buf[0] = 0;
        }
        else
        {
            t = trim_start(t);

            /* Start a new line */
            buf[0] = 0;
        }

        /* t points to a valid line */
        strlcat(buf, t, buflen);
    }

    /* Always append if we found a newline */
    if(newline)
        strlcat(buf, "\n", buflen);
}

/* This file was partially based on proxsmtpd.c
 * 
 * Copyright (c) 2004, Stefan Walter
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the
 *       following disclaimer.
 *     * Redistributions in binary form must reproduce the
 *       above copyright notice, this list of conditions and
 *       the following disclaimer in the documentation and/or
 *       other materials provided with the distribution.
 *     * The names of contributors to this software may not be
 *       used to endorse or promote products derived from this
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 *
 * CONTRIBUTORS
 *  Stef Walter <stef@memberwebs.com>
 */
