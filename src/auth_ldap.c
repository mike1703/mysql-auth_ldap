/***************************************************************************
 *   Copyright (C) 2012 by Infoscope Hellas. All rights reserved.          *
 *   Authors: Charalampos Serenis,                                         *
 *   serenis@dev.infoscope.gr                                              *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.               *
 ***************************************************************************/

// Standard C includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// OS specific includes
#include <dlfcn.h>
#include <syslog.h>

// MySQL specific includes
#include <mysql/mysql.h>
#include <mysql/my_global.h>
#include <mysql/plugin_auth.h>
#include <mysql/client_plugin.h>

// Third party includes
#include <ldap.h>
#include <libconfig.h>

config_t cfg, *cf;
char *CONFIG_LDAP_URI = NULL;
char *CONFIG_DN = NULL;
const char *CONFIG_LIBLDAP = NULL;

// uncomment this for more info logs
//#define DEBUG

// Logging functions.
static void openSysLog(void);
static char* vmkString(const char* format,int *size, va_list ap);
static void error(const char* err, ... );
static void info(const char* message, ... );

// openLDAP wrapper functions.
static int ldap_initialize_wrapper( LDAP**, char* );
static int ldap_set_option_wrapper( LDAP*,int, const void* );
static int ldap_unbind_ext_wrapper( LDAP*, LDAPControl*[], LDAPControl*[] );
static int ldap_sasl_bind_s_wrapper( LDAP*, const char*, const char*,
  struct berval*, LDAPControl*[], LDAPControl*[], struct berval** );
static struct berval* ber_str2bv_wrapper( const char*, ber_len_t, int,
  struct berval*); 

// Function pointers to ldap functions typedefs.
typedef int ( *ldap_initialize_t  )( LDAP**, char*);
typedef int ( *ldap_set_option_t  )( LDAP*, int, const void*);
typedef int ( *ldap_unbind_ext_t  )( LDAP*, LDAPControl*[], LDAPControl*[] );
typedef int ( *ldap_sasl_bind_s_t )( LDAP*, const char*, const char*,
  struct berval*, LDAPControl*[], LDAPControl*[], struct berval** );
typedef struct berval* (*ber_str2bv_t)( const char*, ber_len_t, int,
  struct berval*); 

// Functions pointers to openLDAP functions, used by openLDAP wrapper functions.
static ldap_initialize_t  ldap_initialize_p;
static ldap_set_option_t  ldap_set_option_p;
static ldap_unbind_ext_t  ldap_unbind_ext_p;
static ldap_sasl_bind_s_t ldap_sasl_bind_s_p;
static ber_str2bv_t       ber_str2bv_p;
static char* (*ldap_err2string_p)(int);

// dynamic openLDAP library handle.
static void* libldapHandle = NULL;

// Flag to signal if the syslog is open or not.
static int syslog_open = 0;

// Open syslog for logging
static void openSysLog(void){
  if( syslog_open ) return;
	openlog( "mysql-auth_ldap", LOG_PID, LOG_DAEMON );
	syslog_open = 1;
}

// Log an information message to the system log
static void info(const char* message, ... ){
  
  // va_list struct to load the variable argument list
	va_list ap;
  
  // check if the syslog is open
	if(!syslog_open)
    openSysLog();
  
  // validate printf style error format 
	if(message==NULL){
    // NULL was supplied. Simply log there was an info!
		syslog(LOG_ERR,"info\n");
	}else{
    // generate the C string based on the error format and the va_list
		char *msg;
		int size=0;
		do{
			va_start(ap,message);
			msg=vmkString(message,&size,ap);
			va_end(ap);
		}while(msg==NULL && (size != 0) );
    // Check if the error message got generated without a problem
		if(msg==NULL){
      // there was an error generating the info message. Simply log the info
      // format.
			syslog(LOG_INFO,"info: %s\n",msg);
		}else{
      // log the error message
			syslog(LOG_INFO,"info: %s\n",msg);
      // free the allocated space
			free(msg);
		}
	}
}


// Log a error to the syslog
static void error(const char* err, ... ){
  
  // va_list struct to load the variable argument list
	va_list ap;
  
  // check if the syslog is open
	if(!syslog_open)
    openSysLog();
  
  // validate printf style error format 
	if(err==NULL){
    // NULL was supplied. Simply log there was an error!
		syslog(LOG_ERR,"error\n");
	}else{
    // generate the C string based on the error format and the va_list
		char *msg;
		int size=0;
		do{
			va_start(ap,err);
			msg=vmkString(err,&size,ap);
			va_end(ap);
		}while(msg==NULL && (size != 0) );
    // Check if the error message got generated without a problem
		if(msg==NULL){
      // there was an error generating the error message. Simply log the error
      // format.
			syslog(LOG_ERR,"error: %s\n",err);
		}else{
      // log the error message
			syslog(LOG_ERR,"error: %s\n",msg);
      // free the allocated space
			free(msg);
		}
	}
}

// Create a C string using a printf format string and a va_list
static char* vmkString(const char* format,int *size, va_list ap){
	
	// argument check
	if(format==NULL){
		*size=0;
		return NULL;
	}
	
	// allocate an initial string twice as long as the format string
	if( (*size) == 0 ){
		*size = 2*strlen(format);
	}
	
	// check the size, to avoid security problems
	if( (*size) > (1024) ){
		// do not allocate a string larger than 1Kbyte.
		*size=0;
		return NULL;
	}
	
	char *cstring;
	cstring=(char*)malloc( (*size)*sizeof(char));
	if(cstring==NULL){
		error("vmkString: cannot allocate memory");
		*size=0;
		return NULL;
	}
		
	// pass the format string and the variable argument list to vsnprintf
	int n=vsnprintf(cstring,*size,format,ap);

	// check if vsnprintf returned successfully
	// Until glibc 2.0.6 vsnprintf would return -1 when the output was
	// truncated. 
	if(n>-1 && n< (*size) )
		return cstring;
	
	if(n>-1){
		// glibc is version 2.1 or greater
		// set the exact string size
		*size=n+1;
	}else{
		// old version of glib returns -1
		// double the size
		*size= 2 * (*size);
	}
	
	return NULL;
	
}

static int ldap_initialize_wrapper( LDAP** ldp, char *uri ){
  #ifdef AUTH_LDAP_TEST_API
    return ldap_initialize( ldp, uri );
  #else
    return (*ldap_initialize_p)( ldp, uri );
  #endif
}

static int ldap_set_option_wrapper( LDAP *ld, int option, const void *invalue ){
  #ifdef AUTH_LDAP_TEST_API
    return ldap_set_option( ld, option, invalue );
  #else
    return (*ldap_set_option_p)( ld, option, invalue );
  #endif
}

static int ldap_unbind_ext_wrapper( LDAP *ld, LDAPControl *sctrls[],
    LDAPControl *cctrls[]){
      
  #ifdef AUTH_LDAP_TEST_API
    return ldap_unbind_ext( ld, sctrls, cctrls );
  #else
    return (*ldap_unbind_ext_p)( ld, sctrls, cctrls );
  #endif
}

static int ldap_sasl_bind_s_wrapper( LDAP *ld, const char *dn,
    const char *mechanism, struct berval *cred, LDAPControl *sctrls[],
    LDAPControl *cctrls[], struct berval **servercredp){
      
  #ifdef AUTH_LDAP_TEST_API
    return ldap_sasl_bind_s( ld, dn, mechanism, cred, sctrls, cctrls,
      servercredp );
  #else
    return (*ldap_sasl_bind_s_p)( ld, dn, mechanism, cred, sctrls, cctrls,
      servercredp );
  #endif
    
}

static struct berval* ber_str2bv_wrapper( const char* str, ber_len_t len,
    int dup, struct berval* bv){
      
  #ifdef AUTH_LDAP_TEST_API
    return ber_str2bv( str, len, dup, bv );
  #else
    return (*ber_str2bv_p)( str, len, dup, bv );
  #endif
}

/*
 * 
 * Server plugin
 * 
 */
static int ldap_auth_server(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *myInfo){
  unsigned char *password;
  int pkt_len;

#ifdef DEBUG
  info("ldap_auth_server: server plugin invoked");
#endif
  /* read the password */
  if ((pkt_len= vio->read_packet(vio, &password)) < 0)
    return CR_ERROR;

  myInfo->password_used= PASSWORD_USED_YES;

  //~ /*vio->info(vio, &vio_info);
  //~ if (vio_info.protocol != MYSQL_VIO_SOCKET)
    //~ return CR_ERROR;*/

  LDAP *ld;

#ifdef DEBUG
  info("ldap_auth_server: connecting to LDAP server" );
#endif
  int status = (*ldap_initialize_wrapper)( &ld, CONFIG_LDAP_URI );
  if( status != LDAP_SUCCESS ){
    error("ldap_auth_server: connection to %s failed", CONFIG_LDAP_URI );
    return CR_ERROR;
  }

  int version = LDAP_VERSION3;
  
#ifdef DEBUG
  info("ldap_auth_server: setting LDAP protocol version to 3" );
#endif
  status = (*ldap_set_option_wrapper)( ld, LDAP_OPT_PROTOCOL_VERSION, &version );
  if( status != LDAP_OPT_SUCCESS ){
    error("ldap_auth_server: cannot set LDAP protocol version to 3" );
    (*ldap_unbind_ext_wrapper)( ld, NULL, NULL );
    return CR_ERROR;
  }

  char *username = strdup(myInfo->user_name);
  size_t usernameSize = strlen(username);
  // uid=?,DN
  //  4   1
  size_t dnSize = usernameSize + strlen(CONFIG_DN) + 4;
  char *dn = (char*) malloc( sizeof(char) * (dnSize+1) );
  strcpy( dn, "cn=" );
  strcpy( &dn[3], username );
  dn[3+usernameSize] = ',';
  strcpy( &dn[4+usernameSize], CONFIG_DN );
  free(username);
  //info("ldap_auth_server: supplied password: '%s'", password);
  struct berval* credentials = (*ber_str2bv_wrapper)( (char*)password, 0, 0, NULL );
  if( credentials == NULL ){
    free(dn);
    (*ldap_unbind_ext_wrapper)( ld, NULL, NULL );
    return CR_ERROR;
  }

  // do we need to free the server credentials?
  struct berval* serverCredentials;

#ifdef DEBUG
  info("ldap_auth_server: dn: '%s'", dn);
  info("ldap_auth_server: binding to LDAP server");
#endif
  status = (*ldap_sasl_bind_s_wrapper)( ld, dn, LDAP_SASL_SIMPLE, credentials, NULL, NULL, &serverCredentials);
  //info("ldap_auth_server: ldap_sasl_bind_s returned: %s", (*ldap_err2string_p)(status) );
  //~ ber_bvfree(serverCredentials);
  free(dn);
  (*ldap_unbind_ext_wrapper)( ld, NULL, NULL );

  if( status == LDAP_SUCCESS ){
#ifdef DEBUG
    info("ldap_auth_server: bind succeeded");
#endif
    return CR_OK;
  }
#ifdef DEBUG
  info("ldap_auth_server: bind failed");
#endif
  //info("ldap_auth_server: ldap_sasl_bind_s returned: %s", (*ldap_err2string_p)(status) );
  return CR_ERROR;

  return CR_OK;
}


static struct st_mysql_auth ldap_auth_handler=
{
  MYSQL_AUTHENTICATION_INTERFACE_VERSION,
  "auth_ldap",
  ldap_auth_server
};

static int init(void* omited){
  info("init: loading module auth_ldap");
  // read config file
  const char *_CONFIG_LDAP_URI = NULL;
  const char *_CONFIG_DN = NULL;

  cf = &cfg;
  config_init(cf);

  if (!config_read_file(cf, "/etc/mysql/conf.d/mysql-auth_ldap.cfg")) {
      error("%s:%d - %s\n",
              config_error_file(cf),
              config_error_line(cf),
              config_error_text(cf));
      config_destroy(cf);
      return(EXIT_FAILURE);
  }

  if (config_lookup_string(cf, "ldap.uri", &_CONFIG_LDAP_URI))
  {
      CONFIG_LDAP_URI = strdup(_CONFIG_LDAP_URI);
      info("ldap.uri = %s", CONFIG_LDAP_URI);
  }
  else
      error("ldap.uri is not defined (e.g. ldap://localhost:389)");

  if (config_lookup_string(cf, "ldap.dn", &_CONFIG_DN))
  {
      CONFIG_DN = strdup(_CONFIG_DN);
      info("ldap.dn = %s", CONFIG_DN);
  }
  else
      error("ldap.dn is not defined (e.g. ou=People,dc=example,dc=com)");

  if (config_lookup_string(cf, "ldap.libldap", &CONFIG_LIBLDAP))
  {
      info("ldap.libldap = %s", CONFIG_LIBLDAP);
  }
  else
      error("ldap.libldap is not defined (e.g. /usr/lib64/libldap.so)");
  // end of reading the config file

  info("init: openning openLDAP library");
	void *handle      = dlopen( CONFIG_LIBLDAP, RTLD_LAZY );
  if( handle == NULL ){
    error("init: cannot open library: %s", CONFIG_LIBLDAP);
    return 1;
  }
	void *initialize  = dlsym( handle, "ldap_initialize" );
  if( initialize == NULL ){
    error("init: cannot load symbol: ldap_initialize");
    return 1;
  }
	void *setOption   = dlsym( handle, "ldap_set_option" );
  if( setOption == NULL ){
    error("init: cannot load symbol: ldap_set_option");
    return 1;
  }
	void *unbind      = dlsym( handle, "ldap_unbind_ext" );
  if( unbind == NULL ){
    error("init: cannot load symbol: ldap_unbind_ext");
    return 1;
  }
	void *bind        = dlsym( handle, "ldap_sasl_bind_s" );
  if( bind == NULL ){
    error("init: cannot load symbol: ldap_sasl_bind_s");
    return 1;
  }
	void *ber         = dlsym( handle, "ber_str2bv" );
  if( ber == NULL ){
    error("init: cannot load symbol: ber_str2bv");
    return 1;
  }

	ldap_initialize_p  = (ldap_initialize_t)initialize;
	ldap_set_option_p  = (ldap_set_option_t)setOption;
	ldap_unbind_ext_p  = (ldap_unbind_ext_t)unbind;
	ldap_sasl_bind_s_p = (ldap_sasl_bind_s_t)bind;
	ber_str2bv_p        = (ber_str2bv_t)ber;
  
  void *temp = dlsym( handle, "ldap_err2string" );
  ldap_err2string_p = (char* (*)(int))temp;

	libldapHandle = handle;

	return 0;
}

static int deinit(void* omited){
  info("deinit: unloading module auth_ldap");
  //close libldap dynamic library
	if( libldapHandle != NULL ){
    info("deinit: closing openLDAP library");
    dlclose( libldapHandle );
  }
  //close syslog
  if( syslog_open ){
    info("deinit: closing syslog. Buy!");
    closelog();
  }
  free(CONFIG_LDAP_URI);
  free(CONFIG_DN);
  config_destroy(cf);
	return 0;
}

mysql_declare_plugin(ldap_auth){
  MYSQL_AUTHENTICATION_PLUGIN,         //plugin type
  &ldap_auth_handler,                  //pointer to plugin descriptor
  "auth_ldap",                         //plugin name
  "Charalampos Serenis",               //author
  "LDAP authentication server plugin", //description
  PLUGIN_LICENSE_GPL,                  //license
  init,                                //on load function
  deinit,                              //on unload function
  0x0100,                              //version
  NULL,                                //status vars ??
  NULL,                                //system vars ??
  NULL,                                //reserved
  0,                                   //flags ??
} mysql_declare_plugin_end;



static int ldap_auth_client( MYSQL_PLUGIN_VIO *vio, MYSQL *mysql){

	size_t passwordSize = 0;

	if( mysql->passwd != NULL )
		passwordSize = strlen( mysql->passwd );
	
	++passwordSize;

	// Send password to server plain text
  int status = vio->write_packet( vio, (const unsigned char *)mysql->passwd, passwordSize );

	if( status )
		return CR_ERROR;
	return CR_OK;

}

//http://docs.oracle.com/cd/E17952_01/refman-5.5-en/writing-authentication-plugins.html
mysql_declare_client_plugin(AUTHENTICATION)
  "auth_ldap",                         //plugin name
  "Charalampos Serenis",               //author
  "LDAP authentication client plugin", //description
  {1,0,0},                             //version
  "GPL",                               //license type
  NULL,                                //internal
  NULL,                                //on load function
  NULL,                                //on unload function
  NULL,                                //option handler
  ldap_auth_client                     //pointer to plugin descriptor
mysql_end_client_plugin;
