#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>

unsigned char datablob[116];
char obfuscation_key[16] = "rgca/[204';b/[]/";

/* sub_c770 */
mach_msg_return_t receive_mach_msg(mach_port_t rcv_name, mach_msg_header_t *msg, mach_msg_size_t rcv_size)
{
	return mach_msg(msg, MACH_RCV_MSG, 0, rcv_size, rcv_name, 0, 0);
}

/* sub_cc08 */
char * read_file(char *path, size_t *pSize)
{
	size_t size;
	char *data;
	int fd;
	
	*pSize = 0;
	
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		return 0;
	}

	lseek(fd, 0, SEEK_END);
	size = lseek(fd, 0, SEEK_CUR);
	lseek(fd, 0, SEEK_SET);
	data = (char *) malloc(size);
	if ( !data ) {
		close (fd);
		return 0;
	}

	while ( read(fd, data, size) == -1 )
	{
		if ( *__error() != EAGAIN && *__error() != EINTR )
		{
			free(data);
			return 0;
		}
	}
	*pSize = size;
	close(fd);
	return data;
}

/* sub_cc98 */
int write_file(char *path, const void *buffer, size_t size)
{
	int fd;

	fd = open(path, O_WRONLY|O_TRUNC|O_CREAT, 0644);
	if ( fd < 0 )
	{
		return -1;
	}
	
	if ( write(fd, buffer, size) > -1 )
	{
		close(fd);
		return 0;
	}

	while ( *__error() == EAGAIN || *__error() == EINTR )
	{
		if ( write(fd, buffer, size) >= 0 )
		{
			close(fd);
			return 0;
		}
	}
	
	close(fd);
	return -1;
}

/* sub_cd04 */
int copy_file(const char *dst, const char *src)
{
	int fd_src;
	int fd_dst;
	int bytes_read, bytes_written;
	int retval;
	char buffer[1024];

	fd_src = open(src, O_RDONLY);
	if ( fd_src < 0 ) {
		return -1;
	}
	fd_dst = open(dst, O_WRONLY|O_TRUNC|O_CREAT, 0644);
	if ( fd_dst < 0 ) {
		close(fd_src);
		return -1;
	}
	while ( 1 )
	{
		bytes_read = read(fd_src, buffer, sizeof(buffer));
		if ( bytes_read <= -1 )
		{
			while ( *__error() == EAGAIN || *__error() == EINTR )
			{
				bytes_read = read(fd_src, buffer, sizeof(buffer));
				if (bytes_read <= -1) {
					close(fd_src);
					close(fd_dst);
					return -1;
				}
			}
		}
	  
		if ( bytes_read == 0 )
			break;

		bytes_written = write(fd_dst, buffer, bytes_read);
		if ( bytes_written <= -1 )
		{
			while ( *__error() == EAGAIN || *__error() == EINTR )
			{
				bytes_written = write(fd_dst, buffer, bytes_read);
				if (bytes_written <= -1) {
					close(fd_src);
					close(fd_dst);
					return -1;
				}
			}
		}
		
		if ( bytes_written != bytes_read ) {
			close(fd_src);
			close(fd_dst);
			return -1;
		}
	}
 
	close(fd_src);
	close(fd_dst);
	return 0;
}

/* sub_ce0c */
int deltree(char *directory)
{
	DIR *dirh;
	struct dirent *entry;
	char path[2048];

	dirh = opendir(directory);
	if ( dirh == NULL ) {
		return -1;
	}
	
	for ( entry = readdir(dirh); entry; entry = readdir(dirh) )
	{
		if ( strcmp(&entry->d_name[0], ".") && strcmp(&entry->d_name[0], "..") ) {
			strcpy(path, directory);
			strcat(path, "/");
			strcat(path, &entry->d_name[0]);
			if ( entry->d_type == DT_DIR ) {
				deltree(path);
			} else {
				unlink(path);
			}
		}
	}
	closedir(dirh);
	return (rmdir(directory));
}

/* sub_cedc */
int copy_dylibs()
{
	mkdir("/var/mobile/Media/install", 0777u);
	chown("/var/mobile/Media/install", 0765u, 0765u);
	copy_file("/var/mobile/Media/install/libmis.dylib", "/usr/lib/libmis.dylib");
	copy_file("/var/mobile/Media/install/xpcd_cache.dylib", "/usr/lib/xpcd_cache.dylib");
	return 0;
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

/* sub_e5c8 - (C) code from planetbeing's patchfinder */
uint32_t find_str_r1_r2_bx_lr(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const uint8_t search[] = {0x11, 0x60, 0x70, 0x47};
    void* ptr = memmem(kdata, ksize, search, sizeof(search)) + 1;
    if(!ptr)
        return 0;

    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

/* sub_e5f4 - code in style of planetbeing's patchfinder */
uint32_t find_mov_r0_r1_bx_lr(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const uint8_t search[] = {0x08, 0x46, 0x70, 0x47};
    void* ptr = memmem(kdata, ksize, search, sizeof(search)) + 1;
    if(!ptr)
        return 0;

    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

/* sub_e620 - code in style of planetbeing's patchfinder */
uint32_t find_ldr_r0_r1_bx_lr(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const uint8_t search[] = {0x08, 0x68, 0x70, 0x47};
    void* ptr = memmem(kdata, ksize, search, sizeof(search)) + 1;
    if(!ptr)
        return 0;

    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

/* sub_e64c - (C) code from planetbeing's patchfinder */
uint32_t find_flush_dcache(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const uint8_t search[] = {0x00, 0x00, 0xA0, 0xE3, 0x5E, 0x0F, 0x07, 0xEE};
    void* ptr = memmem(kdata, ksize, search, sizeof(search));
    if(!ptr)
        return 0;

    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

/* sub_e674 - (C) code from planetbeing's patchfinder */
uint32_t find_invalidate_tlb(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const uint8_t search[] = {0x00, 0x00, 0xA0, 0xE3, 0x17, 0x0F, 0x08, 0xEE};
    void* ptr = memmem(kdata, ksize, search, sizeof(search));
    if(!ptr)
        return 0;

    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

/* INLINED CODE */
uint32_t bit_range(uint32_t x, int start, int end)
{
    x = (x << (31 - start)) >> (31 - start);
    x = (x >> end);
    return x;
}

/* INLINED CODE */
uint32_t ror(uint32_t x, int places)
{
    return (x >> places) | (x << (32 - places));
}

/* INLINED CODE */
int thumb_expand_imm_c(uint16_t imm12)
{
    if(bit_range(imm12, 11, 10) == 0)
    {
        switch(bit_range(imm12, 9, 8))
        {
            case 0:
                return bit_range(imm12, 7, 0);
            case 1:
                return (bit_range(imm12, 7, 0) << 16) | bit_range(imm12, 7, 0);
            case 2:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 8);
            case 3:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 16) | (bit_range(imm12, 7, 0) << 8) | bit_range(imm12, 7, 0);
            default:
                return 0;
        }
    } else
    {
        uint32_t unrotated_value = 0x80 | bit_range(imm12, 6, 0);
        return ror(unrotated_value, bit_range(imm12, 11, 7));
    }
}

/* sub_ec5c - (C) code from planetbeing's patchfinder */
int insn_add_reg_rm(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return (*i >> 6) & 7;
    else if((*i & 0xFF00) == 0x4400)
        return (*i >> 3) & 0xF;
    else if((*i & 0xFFE0) == 0xEB00)
        return *(i + 1) & 0xF;
    else
        return 0;
}

/* INLINED CODE from planetbeing's patchfinder */
int insn_is_movt(uint16_t* i)
{
    return (*i & 0xFBF0) == 0xF2C0 && (*(i + 1) & 0x8000) == 0;
}

/* INLINED CODE from planetbeing's patchfinder */
int insn_movt_rd(uint16_t* i)
{
    return (*(i + 1) >> 8) & 0xF;
}

/* INLINED CODE from planetbeing's patchfinder */
int insn_movt_imm(uint16_t* i)
{
    return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
}

/* INLINED CODE from planetbeing's patchfinder */
int insn_is_32bit(uint16_t* i)
{
    return (*i & 0xe000) == 0xe000 && (*i & 0x1800) != 0x0;
}

/* INLINED CODE from planetbeing's patchfinder */
int insn_is_add_reg(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return 1;
    else if((*i & 0xFF00) == 0x4400)
        return 1;
    else if((*i & 0xFFE0) == 0xEB00)
        return 1;
    else
        return 0;
}

/* INLINED CODE from planetbeing's patchfinder */
int insn_is_ldr_literal(uint16_t* i)
{
    return (*i & 0xF800) == 0x4800 || (*i & 0xFF7F) == 0xF85F;
}

/* INLINED CODE from planetbeing's patchfinder */
int insn_ldr_literal_rt(uint16_t* i)
{
    if((*i & 0xF800) == 0x4800)
        return (*i >> 8) & 7;
    else if((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

/* sub_e834 - (C) code from planetbeing's patchfinder */
uint16_t* find_literal_ref(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* insn, uint32_t address)
{
    uint16_t* current_instruction = insn;
    uint32_t value[16];
    memset(value, 0, sizeof(value));

    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_mov_imm(current_instruction))
        {
            value[insn_mov_imm_rd(current_instruction)] = insn_mov_imm_imm(current_instruction);
        } else if(insn_is_ldr_literal(current_instruction))
        {
            uintptr_t literal_address  = (uintptr_t)kdata + ((((uintptr_t)current_instruction - (uintptr_t)kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction);
            if(literal_address >= (uintptr_t)kdata && (literal_address + 4) <= ((uintptr_t)kdata + ksize))
            {
                value[insn_ldr_literal_rt(current_instruction)] = *(uint32_t*)(literal_address);
            }
        } else if(insn_is_movt(current_instruction))
        {
            value[insn_movt_rd(current_instruction)] |= insn_movt_imm(current_instruction) << 16;
        } else if(insn_is_add_reg(current_instruction))
        {
            int reg = insn_add_reg_rd(current_instruction);
            if(insn_add_reg_rm(current_instruction) == 15 && insn_add_reg_rn(current_instruction) == reg)
            {
                value[reg] += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
                if(value[reg] == address)
                {
                    return current_instruction;
                }
            }
        }

        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    return NULL;
}

/* sub_ea4c - (C) code from planetbeing's patchfinder */
uint16_t* find_last_insn_matching(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* current_instruction, int (*match_func)(uint16_t*))
{
    while((uintptr_t)current_instruction > (uintptr_t)kdata)
    {
        if(insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3))
        {
            current_instruction -= 2;
        } else
        {
            --current_instruction;
        }

        if(match_func(current_instruction))
        {
            return current_instruction;
        }
    }

    return NULL;
}

/* INLINED CODE (C) code from planetbeing's patchfinder */
int insn_is_bl(uint16_t* i)
{
    if((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd000) == 0xd000)
        return 1;
    else if((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd001) == 0xc000)
        return 1;
    else
        return 0;
}

/* sub_f578 - (C) code from planetbeing's patchfinder */
int insn_is_push(uint16_t* i)
{
    if((*i & 0xFE00) == 0xB400)
        return 1;
    else if(*i == 0xE92D)
        return 1;
    else if(*i == 0xF84D && (*(i + 1) & 0x0FFF) == 0x0D04)
        return 1;
    else
        return 0;
}

/* sub_ecd4 - (C) code from planetbeing's patchfinder */
uint32_t find_proc_enforce(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find the description.
    uint8_t* proc_enforce_description = memmem(kdata, ksize, "Enforce MAC policy on process operations", sizeof("Enforce MAC policy on process operations"));
    if(!proc_enforce_description)
        return 0;

    // Find what references the description.
    uint32_t proc_enforce_description_address = region + ((uintptr_t)proc_enforce_description - (uintptr_t)kdata);
    uint8_t* proc_enforce_description_ptr = memmem(kdata, ksize, &proc_enforce_description_address, sizeof(proc_enforce_description_address));
    if(!proc_enforce_description_ptr)
        return 0;

    // Go up the struct to find the pointer to the actual data element.
    uint32_t* proc_enforce_ptr = (uint32_t*)(proc_enforce_description_ptr - (5 * sizeof(uint32_t)));
    return *proc_enforce_ptr - region;
}

/* sub_ed1c - code in style of planetbeing's patchfinder */
uint32_t find_vnode_enforce(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find the description.
    uint8_t* proc_enforce_description = memmem(kdata, ksize, "Enforce MAC policy on vnode operations", sizeof("Enforce MAC policy on vnode operations"));
    if(!proc_enforce_description)
        return 0;

    // Find what references the description.
    uint32_t proc_enforce_description_address = region + ((uintptr_t)proc_enforce_description - (uintptr_t)kdata);
    uint8_t* proc_enforce_description_ptr = memmem(kdata, ksize, &proc_enforce_description_address, sizeof(proc_enforce_description_address));
    if(!proc_enforce_description_ptr)
        return 0;

    // Go up the struct to find the pointer to the actual data element.
    uint32_t* proc_enforce_ptr = (uint32_t*)(proc_enforce_description_ptr - (5 * sizeof(uint32_t)));
    return *proc_enforce_ptr - region;
}

/* sub_ea9c - (C) code from planetbeing's patchfinder */
static uint32_t find_pc_rel_value(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* insn, int reg)
{
    // Find the last instruction that completely wiped out this register
    int found = 0;
    uint16_t* current_instruction = insn;
    while((uintptr_t)current_instruction > (uintptr_t)kdata)
    {
        if(insn_is_32bit(current_instruction - 2))
        {
            current_instruction -= 2;
        } else
        {
            --current_instruction;
        }

        if(insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg)
        {
            found = 1;
            break;
        }

        if(insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg)
        {
            found = 1;
            break;
        }
    }

    if(!found)
        return 0;

    // Step through instructions, executing them as a virtual machine, only caring about instructions that affect the target register and are commonly used for PC-relative addressing.
    uint32_t value = 0;
    while((uintptr_t)current_instruction < (uintptr_t)insn)
    {
        if(insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg)
        {
            value = insn_mov_imm_imm(current_instruction);
        } else if(insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg)
        {
            value = *(uint32_t*)(kdata + (((((uintptr_t)current_instruction - (uintptr_t)kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction)));
        } else if(insn_is_movt(current_instruction) && insn_movt_rd(current_instruction) == reg)
        {
            value |= insn_movt_imm(current_instruction) << 16;
        } else if(insn_is_add_reg(current_instruction) && insn_add_reg_rd(current_instruction) == reg)
        {
            if(insn_add_reg_rm(current_instruction) != 15 || insn_add_reg_rn(current_instruction) != reg)
            {
                // Can't handle this kind of operation!
                return 0;
            }

            value += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
        }

        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    return value;
}

/* sub_e888 - (C) code from planetbeing's patchfinder */
uint32_t find_pmap_location(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find location of the pmap_map_bd string.
    uint8_t* pmap_map_bd = memmem(kdata, ksize, "\"pmap_map_bd\"", sizeof("\"pmap_map_bd\""));
    if(!pmap_map_bd)
        return 0;

    // Find a reference to the pmap_map_bd string. That function also references kernel_pmap
    uint16_t* ptr = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)pmap_map_bd - (uintptr_t)kdata);
    if(!ptr)
        return 0;

    // Find the end of it.
    const uint8_t search_function_end[] = {0xF0, 0xBD};
    ptr = memmem(ptr, ksize - ((uintptr_t)ptr - (uintptr_t)kdata), search_function_end, sizeof(search_function_end));
    if(!ptr)
        return 0;

    // Find the last BL before the end of it. The third argument to it should be kernel_pmap
    uint16_t* bl = find_last_insn_matching(region, kdata, ksize, ptr, insn_is_bl);
    if(!bl)
        return 0;

    // Find the last LDR R2, [R*] before it that's before any branches. If there are branches, then we have a version of the function that assumes kernel_pmap instead of being passed it.
    uint16_t* ldr_r2 = NULL;
    uint16_t* current_instruction = bl;
    while((uintptr_t)current_instruction > (uintptr_t)kdata)
    {
        if(insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3))
        {
            current_instruction -= 2;
        } else
        {
            --current_instruction;
        }

        if(insn_ldr_imm_rt(current_instruction) == 2 && insn_ldr_imm_imm(current_instruction) == 0)
        {
            ldr_r2 = current_instruction;
            break;
        } else if(insn_is_b_conditional(current_instruction) || insn_is_b_unconditional(current_instruction))
        {
            break;
        }
    }

    // The function has a third argument, which must be kernel_pmap. Find out its address
    if(ldr_r2)
        return find_pc_rel_value(region, kdata, ksize, ldr_r2, insn_ldr_imm_rn(ldr_r2));

    // The function has no third argument, Follow the BL.
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)
        return 0;

    // Find the first PC-relative reference in this function.
    int found = 0;
    int rd;
    current_instruction = (uint16_t*)(kdata + target);
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15)
        {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }

        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    if(!found)
        return 0;

    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

/* sub_ec94 - (C) code from planetbeing's patchfinder */
int insn_add_reg_rd(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return (*i & 7);
    else if((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4) ;
    else if((*i & 0xFFE0) == 0xEB00)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

/* sub_104e4 - (C) code from planetbeing's patchfinder */
int insn_add_reg_rn(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return ((*i >> 3) & 7);
    else if((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4) ;
    else if((*i & 0xFFE0) == 0xEB00)
        return (*i & 0xF);
    else
        return 0;
}

/* sub_104a8 - (C) code from planetbeing's patchfinder */
int insn_ldr_literal_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x4800)
        return (*i & 0xF) << 2;
    else if((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) & 0xFFF) * (((*i & 0x0800) == 0x0800) ? 1 : -1);
    else
        return 0;
}

/* sub_f920 - (C) code from planetbeing's patchfinder */
int insn_is_mov_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return 1;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return 1;
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return 1;
    else
        return 0;
}

/* sub_f964 - (C) code from planetbeing's patchfinder */
int insn_mov_imm_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return *i & 0xF;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
    else
        return 0;
}

/* sub_fa18 - (C) code from planetbeing's patchfinder */
int insn_mov_imm_rd(uint16_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return (*i >> 8) & 7;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}



/* InitFunc_0 */

__attribute__((constructor))
void InitFunc()
{
	datablob[0] = 0xD8;
	datablob[1] = 0xC5;
	datablob[2] = 0xD0;
	datablob[3] = 0xC9;
	datablob[4] = 0xFA;
	datablob[5] = 0xD1;
	datablob[6] = 0xFA;
	datablob[7] = 0xE1;
	datablob[8] = 0xD;
	datablob[9] = 0xE5;
	datablob[10] = 0xF3;
	datablob[11] = 0xA0;
	datablob[12] = 0xE3;
	datablob[13] = 0xD2;
	datablob[14] = 0xFA;
	datablob[15] = 0xD8;
	datablob[16] = 0xC5;
	datablob[17] = 0xC8;
	datablob[18] = 0xC5;
	datablob[19] = 8;
	datablob[20] = 0xA6;
	datablob[21] = 0xF4;
	datablob[22] = 0xE0;
	datablob[23] = 0xF8;
	datablob[24] = 0xEF;
	datablob[25] = 0xE6;
	datablob[26] = 0x9E;
	datablob[27] = 0xE7;
	datablob[28] = 0xF8;
	datablob[29] = 0xD8;
	datablob[30] = 0xC5;
	datablob[31] = 0xC8;
	datablob[32] = 0xC5;
	datablob[33] = 8;
	datablob[34] = 0xBB;
	datablob[35] = 0xE1;
	datablob[36] = 0xF2;
	datablob[37] = 0xF7;
	datablob[38] = 0xF0;
	datablob[39] = 5;
	datablob[40] = 0xA4;
	datablob[41] = 0xFA;
	datablob[42] = 0xCA;
	datablob[43] = 0xD1;
	datablob[44] = 0xE9;
	datablob[45] = 0xB4;
	datablob[46] = 4;
	datablob[47] = 0xD8;
	datablob[48] = 0xC5;
	datablob[49] = 0xC8;
	datablob[50] = 0xC5;
	datablob[51] = 8;
	datablob[52] = 0xB4;
	datablob[53] = 0xF8;
	datablob[54] = 0xEF;
	datablob[55] = 0xFE;
	datablob[56] = 0xF1;
	datablob[57] = 0xFB;
	datablob[58] = 0xAD;
	datablob[59] = 9;
	datablob[60] = 0xD4;
	datablob[61] = 0xD1;
	datablob[62] = 0xE7;
	datablob[63] = 0xB9;
	datablob[64] = 0xB0;
	datablob[65] = 0;
	datablob[66] = 0xD8;
	datablob[67] = 0xC5;
	datablob[68] = 0xD3;
	datablob[69] = 0xAF;
	datablob[70] = 0xE7;
	datablob[71] = 0xC6;
	datablob[72] = 14;
	datablob[73] = 0xF9;
	datablob[74] = 0xFA;
	datablob[75] = 0xDF;
	datablob[76] = 0xF2;
	datablob[77] = 0xB3;
	datablob[78] = 9;
	datablob[79] = 0xD4;
	datablob[80] = 0xD9;
	datablob[81] = 0xF9;
	datablob[82] = 0x9E;
	datablob[83] = 4;
	datablob[84] = 0xBD;
	datablob[85] = 0x9F;
	datablob[86] = 0xB0;
	datablob[87] = 0xAB;
	datablob[88] = 0xFA;
	datablob[89] = 0xCC;
	datablob[90] = 0x13;
	datablob[91] = 0xF2;
	datablob[92] = 0xE4;
	datablob[93] = 0xE1;
	datablob[94] = 0xE6;
	datablob[95] = 0xA8;
	datablob[96] = 0xFC;
	datablob[97] = 0xCC;
	datablob[98] = 0xCF;
	datablob[99] = 0xFA;
	datablob[100] = 0xF;
	datablob[101] = 0xBD;
	datablob[102] = 0x9F;
	datablob[103] = 0xB0;
	datablob[104] = 0xAB;
	datablob[105] = 0xFA;
	datablob[106] = 0xCC;
	datablob[107] = 0x18;
	datablob[108] = 0xFB;
	datablob[109] = 0xDD;
	datablob[110] = 0xDF;
	datablob[111] = 0xE6;
	datablob[112] = 0xB1;
	datablob[113] = 0xEB;
	datablob[114] = 0xD4;
	datablob[115] = 0xFA;
}

/* sub_11808 */
void deobfuscate_strings()
{
	char buffer[100];
	memset(buffer, 0, 100);
	int i;

	memset(buffer, 0, 100);
	for (i=0; i<=15; i++) buffer[i] = (datablob[i] + 99)^obfuscation_key[i&15];
	printf("string1: %s\n", buffer);

	memset(buffer, 0, 100);
	for (i=0; i<=14; i++) buffer[i] = (datablob[i+0xf] + 99)^obfuscation_key[i&15];
	printf("string2: %s\n", buffer);

	memset(buffer, 0, 100);
	for (i=0; i<=19; i++) buffer[i] = (datablob[i+0x2f] + 99)^obfuscation_key[i&15];
	printf("string3: %s\n", buffer);

	memset(buffer, 0, 100);
	for (i=0; i<=18; i++) buffer[i] = (datablob[i+0x1d] + 99)^obfuscation_key[i&15];
	printf("string4: %s\n", buffer);

	memset(buffer, 0, 100);
	for (i=0; i<=18; i++) buffer[i] = (datablob[i+0x42] + 99)^obfuscation_key[i&15];
	printf("string5: %s\n", buffer);

	memset(buffer, 0, 100);
	for (i=0; i<=17; i++) buffer[i] = (datablob[i+0x54] + 99)^obfuscation_key[i&15];
	printf("string6: %s\n", buffer);

	memset(buffer, 0, 100);
	for (i=0; i<=15; i++) buffer[i] = (datablob[i+0x65] + 99)^obfuscation_key[i&15];
	printf("string7: %s\n", buffer);
}

/* sub_119c4 */
char * get_IOPMrootDomain()
{
	return "IOPMrootDomain";
}

/* sub_119d4 */
char * get_IOHIDResource()
{
	return "IOHIDResource";
}

/* sub_119e4 */
char * get_IOHIDLibUserClient()
{
	return "IOHIDLibUserClient";
}

/* sub_119f4 */
char * get_IOHIDEventService()
{
	return "IOHIDEventService";
}

/* sub_11a04 */
char * get_IOUserClientClass()
{
	return "IOUserClientClass";
}

/* sub_11a14 */
char * get_ReportDescriptor()
{
	return "ReportDescriptor";
}

/* sub_11a24 */
char * get_ReportInterval()
{
	return "ReportInterval";
}

/* start */
int main(int argc, char **argv, char **envp)
{
	/* not yet implemented */
	
	
	/* DEBUG */
	deobfuscate_strings();
}