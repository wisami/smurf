#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <signal.h>
#include "smurf.h"

#define STR_OPTION "AaDhi:c:"

struct option long_opt[] = {
	{"address", 0, 0, 'a'},
	{"ascii", 0, 0, 'A'},
	{"devices", 0, 0, 'D'},
	{"interface", 1, 0, 'i'},
	{"count", 1, 0, 'c'},
	{"help", 0, 0, 'h'},
	{0, 0, 0, 0}
};

int main(int argc, char *argv[])
{
	int option;
	int option_index;

	signal(SIGINT, exit_smurf);

	struct list_options lopt;
	init_list_options_default(&lopt);

	while((option = getopt_long(argc, argv, STR_OPTION, long_opt, &option_index)) != -1) {
		switch(option) {
			case 'A':
			lopt.Aflag = true;
			break;

			case 'h':
			lopt.hflag = true;
			break;

			case 'D':
			lopt.Dflag = true;
			break;

			case 'a':
			lopt.aflag = true;
			break;

			case 'i':
			lopt.iflag = true;
			lopt.ivalue = optarg;
			break;

			case 'c':
			lopt.cflag = true;
			lopt.cvalue = atoi(optarg);
			break;

			default:
			printf("-h (--help) вызов справки\n");
			exit(EXIT_SUCCESS);
		}
	}

	if(lopt.aflag || lopt.Dflag || lopt.hflag) {
		if(lopt.aflag) print_network_address(&lopt);
		if(lopt.Dflag) print_list_devices();
		if(lopt.hflag) print_usage();

		exit(EXIT_SUCCESS);
	}

	to_sniff(&lopt);

	print_num_packets();

	return 0;
}