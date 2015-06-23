#include <mach/mach.h>
#include <mach/message.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>

/* sub_c770 */
mach_msg_return_t receive_mach_msg(mach_port_t rcv_name, mach_msg_header_t *msg, mach_msg_size_t rcv_size)
{
	return mach_msg(msg, MACH_RCV_MSG, 0, rcv_size, rcv_name, 0, 0);
}

/* sub_e568 */
void setup_watchdog_timer(int value)
{
	io_service_t timerservice = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOWatchDogTimer"));
	if (timerservice != 0) {
		CFNumberRef cfval = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &value);
		IORegistryEntrySetCFProperties(timerservice, cfval);
		IOObjectRelease(timerservice);
		CFRelease(cfval);
	}
}

/* start */
int main(int argc, char **argv, char **envp)
{
	/* not yet implemented */
}