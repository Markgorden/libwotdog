/*
 Authors: ZhangXuelian
 	


 Changes:
 	
	
*/

#include "server.h"

#define MAX_OPTIONS 40
#define MAX_CONF_FILE_LINE_SIZE (8 * 1024)
static int exit_flag;
static char config_file[PATH_MAX];  // Set by process_command_line_arguments()
#define DIRSEP '\\'
#if !defined(CONFIG_FILE)
#define CONFIG_FILE "server.conf"
#endif /* !CONFIG_FILE */
#define ENTRIES_PER_CONFIG_OPTION 3

static void verify_document_root(const char *root) 
{
	const char *p, *path;
	char buf[PATH_MAX];
	struct stat st;

	path = root;
	if ((p = strchr(root, ',')) != NULL && (size_t) (p - root) < sizeof(buf)) {
		memcpy(buf, root, p - root);
		buf[p - root] = '\0';
		path = buf;
	}

	if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) 
	{
		printf("Invalid root directory: [%s]: %s", root, strerror(errno));
	}
}

static char *sdup(const char *str) {
	char *p;
	if ((p = (char *) malloc(strlen(str) + 1)) != NULL) 
	{
		strcpy(p, str);
	}
	return p;
}

static void set_option(char **options, const char *name, const char *value) 
{
	int i;

	if (!strcmp(name, "document_root") || !(strcmp(name, "r"))) {
		verify_document_root(value);
	}

	for (i = 0; i < MAX_OPTIONS - 3; i++) {
		if (options[i] == NULL) {
			options[i] = sdup(name);
			options[i + 1] = sdup(value);
			options[i + 2] = NULL;
			break;
		}
	}

	if (i == MAX_OPTIONS - 3) {
		printf("%s", "Too many options specified");
	}
}

void process_command_line_arguments(char *argv[], char **options) 
{
	char line[MAX_CONF_FILE_LINE_SIZE], opt[sizeof(line)], val[sizeof(line)], *p;
	FILE *fp = NULL;
	size_t i, cmd_line_opts_start = 1, line_no = 0;

	options[0] = NULL;

	// Should we use a config file ?
	if (argv[1] != NULL && argv[1][0] != '-') {
		snprintf(config_file, sizeof(config_file), "%s", argv[1]);
		cmd_line_opts_start = 2;
	} else if ((p = strrchr(argv[0], DIRSEP)) == NULL) {
		// No command line flags specified. Look where binary lives
		snprintf(config_file, sizeof(config_file), "%s", CONFIG_FILE);
	} else {
		snprintf(config_file, sizeof(config_file), "%.*s%c%s",
			(int) (p - argv[0]), argv[0], DIRSEP, CONFIG_FILE);
	}

	fp = fopen(config_file, "r");

	// If config file was set in command line and open failed, die
	if (cmd_line_opts_start == 2 && fp == NULL) {
		printf("Cannot open config file %s: %s", config_file, strerror(errno));
	}

	// Load config file settings first
	if (fp != NULL) {
		fprintf(stderr, "Loading config file %s\n", config_file);

		// Loop over the lines in config file
		while (fgets(line, sizeof(line), fp) != NULL) {

			line_no++;

			// Ignore empty lines and comments
			if (line[0] == '#' || line[0] == '\n')
				continue;
			if (sscanf(line, "%s %[^\r\n#]", opt, val) != 2) {
				printf("%s: line %d is invalid", config_file, (int) line_no);
			}
			set_option(options, opt, val);
		}
		(void) fclose(fp);
	}
}

static void my_strlcpy(register char *dst, register const char *src, size_t n) {
  for (; *src != '\0' && n > 1; n--) {
    *dst++ = *src++;
  }
  *dst = '\0';
}

static int my_lowercase(const char *s) {
  return tolower(* (const unsigned char *) s);
}

static int my_strncasecmp(const char *s1, const char *s2, size_t len) {
  int diff = 0;

  if (len > 0)
    do {
      diff = my_lowercase(s1++) - my_lowercase(s2++);
    } while (diff == 0 && s1[-1] != '\0' && --len > 0);

  return diff;
}

static int my_strcasecmp(const char *s1, const char *s2) {
  int diff;

  do {
    diff = my_lowercase(s1++) - my_lowercase(s2++);
  } while (diff == 0 && s1[-1] != '\0');

  return diff;
}

static char * my_strndup(const char *ptr, size_t len) {
  char *p;

  if ((p = (char *) malloc(len + 1)) != NULL) {
    my_strlcpy(p, ptr, len + 1);
  }
  return p;
}

static char * my_strdup(const char *str) {
  return my_strndup(str, strlen(str));
}

static void free_config(char ** config) 
{
	int i;
	// Deallocate config parameters
	for (i = 0; i < NUM_OPTIONS; i++) 
	{
		if (config[i] != NULL)
			free(config[i]);
	}
}

static int get_option_index(const char *name)
{
	int i;

	for (i = 0; config_options[i] != NULL; i += ENTRIES_PER_CONFIG_OPTION) 
	{
		if (strcmp(config_options[i], name) == 0 ||
			strcmp(config_options[i + 1], name) == 0)
		{
			return i / ENTRIES_PER_CONFIG_OPTION;
		}
	}
	return -1;
}

void get_config(char ** config, const char **options) 
{
  const char *name, *value, *default_value;
  int i;

  while (options && (name = *options++) != NULL) 
  {
	  if ((i = get_option_index(name)) == -1) 
	  {
		  printf("Invalid option: %s", name);
		  free_config(config);
		  return NULL;
	  } 
	  else if ((value = *options++) == NULL) 
	  {
		  printf("%s: option value cannot be NULL", name);
		  free_config(config);
		  return NULL;
	  }
	  if (config[i] != NULL) 
	  {
		  printf("%s: duplicate option", name);
	  }
	  config[i] = my_strdup(value);
	  printf(("[%s] -> [%s]", name, value));
  }

  // Set default value if needed
  for (i = 0; config_options[i * ENTRIES_PER_CONFIG_OPTION] != NULL; i++)
  {
	  default_value = config_options[i * ENTRIES_PER_CONFIG_OPTION + 2];
	  if (config[i] == NULL && default_value != NULL) 
	  {
		  config[i] = my_strdup(default_value);
		  printf(("Setting default: [%s] -> [%s]",config_options[i * ENTRIES_PER_CONFIG_OPTION + 1],default_value));
	  }
  }
}
