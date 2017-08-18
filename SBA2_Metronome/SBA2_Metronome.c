#include <stdlib.h>
#include <stdio.h>
#include <sys/iofunc.h>
#include <sys/dispatch.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/netmgr.h>
#include <sys/neutrino.h>

#define MY_PULSE_CODE   _PULSE_CODE_MINAVAIL

char data[255];
int tableIndex;
int bpm;
int timesigtop;
int timesigbottom;

timer_t                 timer_id;

int t[8][3] = {
		{2,	4,	4},
		{3,	4,	6},
		{4,	4,	8},
		{5,	4,	10},
		{3,	8,	6},
		{6,	8,	6},
		{9,	8,	9},
		{12, 8,	12}
};

const char *output[8] = {
		"|1&2&",
		"|1&2&3&",
		"|1&2&3&4&",
		"|1&2&3&4-5-",
		"|1-2-3-",
		"|1&a2&a",
		"|1&a2&a3&a",
		"|1&a2&a3&a4&a"
};

typedef union {
        struct _pulse   pulse;
        char msg[255];
} my_message_t;

/*
 * A second thread would be created for when the
 * pausing would occur. The thread would block the child thread
 * and reset the timer after the xxx specified number of seconds.
 * Inside the IO_WRITE function a check would be made to check
 * for a pause and split the string msg to identify the amount
 * of seconds to pause the metronome for. The paused seconds
 * would be saved as a global variable and used in the pausing
 * thread.
 */

void* outputThread(void* arg){
	struct sigevent         event;
	struct itimerspec       itime;
	int                     chid;
	int                     rcvid;
	my_message_t            msg;
	int 					counter = 0;
	double 					secperbeat;
	long 					nanosecs;

	chid = ChannelCreate(0);

	event.sigev_notify = SIGEV_PULSE;
	event.sigev_coid = ConnectAttach(ND_LOCAL_NODE, 0, chid, _NTO_SIDE_CHANNEL, 0);
	event.sigev_priority = getprio(0);
	event.sigev_code = MY_PULSE_CODE;
	timer_create(CLOCK_REALTIME, &event, &timer_id);

	// This would calculate the time for the timer to use for each beat
	secperbeat = ((60 / (double)bpm) * (double)timesigtop) / (double)t[tableIndex][2];
	nanosecs = secperbeat * 1000000000;

	itime.it_value.tv_sec = secperbeat;
	itime.it_value.tv_nsec = nanosecs;
	itime.it_interval.tv_sec = secperbeat;
	itime.it_interval.tv_nsec = nanosecs;
	timer_settime(timer_id, 0, &itime, NULL);

	/* I have some bug going on with my eclipse where the output buffer
	 * isn't getting flushed so nothing prints unless I used \n at the
	 * end of every line, this function below seems to fix it though */
	setvbuf (stdout, NULL, _IONBF, 0);
	for (;;) {
	    rcvid = MsgReceive(chid, &msg, sizeof(msg), NULL);
	    if (rcvid == 0) { /* we got a pulse */
	         if (msg.pulse.code == MY_PULSE_CODE) {
	         	if(counter == 0) {
	         		printf("%c%c", output[tableIndex][0], output[tableIndex][1]);
	          		counter = 2;
	           	} else if (counter == t[tableIndex][2]){
	           		printf("%c", output[tableIndex][counter]);
	           		counter = 0;
	           	} else {
	           		printf("%c", output[tableIndex][counter]);
	           		counter++;
	           	}
	         } /* else other pulses ... */
	    } /* else other messages ... */
	}
	return EXIT_SUCCESS;
}

int io_read(resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *ocb)
{
	int nb;

	if(data == NULL)
		return 0;

	nb = strlen(data);

	//test to see if we have already sent the whole message.
	if (ocb->offset == nb)
		return 0;

	//We will return which ever is smaller the size of our data or the size of the buffer
	nb = min(nb, msg->i.nbytes);

	//Set the number of bytes we will return
	_IO_SET_READ_NBYTES(ctp, nb);

	//Copy data into reply buffer.
	SETIOV(ctp->iov, data, nb);

	//update offset into our data used to determine start position for next read.
	ocb->offset += nb;

	//If we are going to send any bytes update the access time for this resource.
	if (nb > 0)
		ocb->attr->flags |= IOFUNC_ATTR_ATIME;

	return(_RESMGR_NPARTS(1));
}

int io_write(resmgr_context_t *ctp, io_write_t *msg, RESMGR_OCB_T *ocb)
{
    int nb = 0;

	if( msg->i.nbytes == ctp->info.msglen - (ctp->offset + sizeof(*msg) ))
	{
		/* have all the data */
		char *buf;
		buf = (char *)(msg+1);

		strcpy(data, buf);

		nb = msg->i.nbytes;
	}
    _IO_SET_WRITE_NBYTES (ctp, nb);

    if (msg->i.nbytes > 0)
        ocb->attr->flags |= IOFUNC_ATTR_MTIME | IOFUNC_ATTR_CTIME;

    return (_RESMGR_NPARTS (0));
}

int io_open(resmgr_context_t *ctp, io_open_t *msg, RESMGR_HANDLE_T *handle, void *extra)
{
	return (iofunc_open_default (ctp, msg, handle, extra));
}

int main(int argc, char *argv[]) {
	dispatch_t* dpp;
	resmgr_io_funcs_t io_funcs;
	resmgr_connect_funcs_t connect_funcs;
	iofunc_attr_t ioattr;
	dispatch_context_t   *ctp;
	pthread_attr_t attr;

	int id;

	if(argc != 4){
		printf("Invalid number of arguments.(Ex. ./metronome beats-per-minute time-signature-top time-signature-bottom\n");
		return EXIT_FAILURE;
	}

	bpm = atoi(argv[1]);
	timesigtop = atoi(argv[2]);
	timesigbottom = atoi(argv[3]);

	if(timesigtop == 2 && timesigbottom == 4)
		tableIndex = 0;
	else if (timesigtop == 3 && timesigbottom == 4)
		tableIndex = 1;
	else if (timesigtop == 4 && timesigbottom == 4)
		tableIndex = 2;
	else if(timesigtop == 5 && timesigbottom == 4)
		tableIndex = 3;
	else if(timesigtop == 3 && timesigbottom == 8)
		tableIndex = 4;
	else if(timesigtop == 6 && timesigbottom == 8)
		tableIndex = 5;
	else if (timesigtop == 9 && timesigbottom == 8)
		tableIndex = 6;
	else if (timesigtop == 12 && timesigbottom == 8)
		tableIndex = 7;
	else {
		printf("Incorrect input for time-signature-top or time-signature-bottom.\n");
		return EXIT_FAILURE;
	}

	dpp = dispatch_create();
	iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &connect_funcs, _RESMGR_IO_NFUNCS, &io_funcs);
	connect_funcs.open = io_open;
	io_funcs.read = io_read;
	io_funcs.write = io_write;

	iofunc_attr_init(&ioattr, S_IFCHR | 0666, NULL, NULL);

	id = resmgr_attach(dpp, NULL, "/dev/local/metronome", _FTYPE_ANY, NULL, &connect_funcs, &io_funcs, &ioattr);

	ctp = dispatch_context_alloc(dpp);

	pthread_attr_init(&attr);
	pthread_create(NULL, &attr, &outputThread, NULL);
	pthread_attr_destroy(&attr);

	while(1) {
		ctp = dispatch_block(ctp);
		dispatch_handler(ctp);
	}

	return EXIT_SUCCESS;
}
