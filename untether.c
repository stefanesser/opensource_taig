#include <mach/mach.h>
#include <mach/message.h>

/* sub_c770 */
mach_msg_return_t receive_mach_msg(mach_port_t rcv_name, mach_msg_header_t *msg, mach_msg_size_t rcv_size)
{
	return mach_msg(msg, MACH_RCV_MSG, 0, rcv_size, rcv_name, 0, 0);
}

/* start */
int main(int argc, char **argv, char **envp)
{
	/* not yet implemented */
}