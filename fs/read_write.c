/*************************************************************************//**
 *****************************************************************************
 * @file   read_write.c
 * @brief  
 * @author Forrest Y. Yu
 * @date   2008
 *****************************************************************************
 *****************************************************************************/

#include "type.h"
#include "stdio.h"
#include "const.h"
#include "protect.h"
#include "string.h"
#include "fs.h"
#include "proc.h"
#include "tty.h"
#include "console.h"
#include "global.h"
#include "keyboard.h"
#include "proto.h"

/* 文件加解密 */
#define ENC_MAGIC 0x31434E45  // 'ENC1'
#define ENC_FLAG_ENCRYPTED 0x01

static inline u32 inode_get_u32(const u8* p)
{
	u32 v;
	memcpy(&v, p, sizeof(v));
	return v;
}

static inline void inode_set_u32(u8* p, u32 v)
{
	memcpy(p, &v, sizeof(v));
}

static inline int inode_is_encrypted(const struct inode* pin)
{
	// 只对普通文件加密；目录不加密
	if ( (pin->i_mode & I_TYPE_MASK) != I_REGULAR ) return 0;
	// 读取标志，利用inode的_unused字段存储
	u32 magic = inode_get_u32((const u8*)pin->_unused + 0);
	u8  flag  = *((const u8*)pin->_unused + 4);
	return (magic == ENC_MAGIC) && (flag & ENC_FLAG_ENCRYPTED);
}

static inline void inode_mark_encrypted(struct inode* pin)
{
	if ( (pin->i_mode & I_TYPE_MASK) != I_REGULAR ) return;
	inode_set_u32((u8*)pin->_unused + 0, ENC_MAGIC);
	*((u8*)pin->_unused + 4) |= ENC_FLAG_ENCRYPTED;
}

// 加解密函数（）
static void crypt_buf(u8* buf, int len, const struct inode* pin, u32 file_off )
{
    u32 key = 0x9E3779B9u ^ (u32)pin->i_num ^ file_off;
    for (int i = 0; i < len; i++) {
        key ^= (key << 13);
        key ^= (key >> 17);
        key ^= (key << 5);
        buf[i] ^= (u8)(key & 0xFF);
    }
}

/* 把一个“未加密普通文件”迁移为“已加密普通文件”（原地改写扇区） */
static void ensure_file_encrypted(struct inode* pin)
{
	//return; // 暂时禁用该功能
	if ( (pin->i_mode & I_TYPE_MASK) != I_REGULAR ) return;
	if (inode_is_encrypted(pin)) return;

	/* 空文件：直接打标记即可 */
	if (pin->i_size == 0) {
		inode_mark_encrypted(pin);
		sync_inode(pin);
		return;
	}

	/* 逐扇区读出明文 -> 加密 -> 写回 */
	u32 left = pin->i_size;
	u32 file_off = 0;
	u32 sect = pin->i_start_sect;

	while (left > 0) {
		int n = (left > SECTOR_SIZE) ? SECTOR_SIZE : (int)left;

		rw_sector(DEV_READ, pin->i_dev, sect * SECTOR_SIZE,
		          SECTOR_SIZE, TASK_FS, fsbuf);

		/* 很关键：把最后一个扇区“文件末尾之后”的区域清零，
		   否则以后扩展文件时，那些字节解密出来可能是脏数据 */
		if (n < SECTOR_SIZE) {
			memset(fsbuf + n, 0, SECTOR_SIZE - n);
		}

		crypt_buf((u8*)fsbuf, SECTOR_SIZE, pin, file_off);

		rw_sector(DEV_WRITE, pin->i_dev, sect * SECTOR_SIZE,
		          SECTOR_SIZE, TASK_FS, fsbuf);

		left -= n;
		file_off += SECTOR_SIZE;
		sect++;
	}

	inode_mark_encrypted(pin);
	sync_inode(pin);
}


/*****************************************************************************
 *                                do_rdwt
 *****************************************************************************/
/**
 * Read/Write file and return byte count read/written.
 *
 * Sector map is not needed to update, since the sectors for the file have been
 * allocated and the bits are set when the file was created.
 * 
 * @return How many bytes have been read/written.
 *****************************************************************************/
PUBLIC int do_rdwt()
{
	int fd = fs_msg.FD;	/**< file descriptor. */
	void * buf = fs_msg.BUF;/**< r/w buffer */
	int len = fs_msg.CNT;	/**< r/w bytes */

	int src = fs_msg.source;		/* caller proc nr. */

	assert((pcaller->filp[fd] >= &f_desc_table[0]) &&
	       (pcaller->filp[fd] < &f_desc_table[NR_FILE_DESC]));

	if (!(pcaller->filp[fd]->fd_mode & O_RDWR))
		return 0;

	int pos = pcaller->filp[fd]->fd_pos;

	struct inode * pin = pcaller->filp[fd]->fd_inode;

	assert(pin >= &inode_table[0] && pin < &inode_table[NR_INODE]);

	int imode = pin->i_mode & I_TYPE_MASK;

	if (imode == I_CHAR_SPECIAL) {
		int t = fs_msg.type == READ ? DEV_READ : DEV_WRITE;
		fs_msg.type = t;

		int dev = pin->i_start_sect;
		assert(MAJOR(dev) == 4);

		fs_msg.DEVICE	= MINOR(dev);
		fs_msg.BUF	= buf;
		fs_msg.CNT	= len;
		fs_msg.PROC_NR	= src;
		assert(dd_map[MAJOR(dev)].driver_nr != INVALID_DRIVER);
		send_recv(BOTH, dd_map[MAJOR(dev)].driver_nr, &fs_msg);
		assert(fs_msg.CNT == len);

		return fs_msg.CNT;
	}
	else {
		assert(pin->i_mode == I_REGULAR || pin->i_mode == I_DIRECTORY);
		assert((fs_msg.type == READ) || (fs_msg.type == WRITE));

		int pos_end;
		int bytes_left;
		if (fs_msg.type == READ) {
			pos_end = min(pos + len, pin->i_size);
			bytes_left = min(len, pin->i_size - pos);
		}
		else {		/* WRITE */
			pos_end = min(pos + len, pin->i_nr_sects * SECTOR_SIZE);
			bytes_left = len;
		}

		int off = pos % SECTOR_SIZE;
		int rw_sect_min=pin->i_start_sect+(pos>>SECTOR_SIZE_SHIFT);
		int rw_sect_max=pin->i_start_sect+(pos_end>>SECTOR_SIZE_SHIFT);

		int chunk = min(rw_sect_max - rw_sect_min + 1,
				FSBUF_SIZE >> SECTOR_SIZE_SHIFT);

		int bytes_rw = 0;
		int i;
		int enc = inode_is_encrypted(pin);

		if (fs_msg.type == WRITE) {
			// 对老的明文文件：先整文件迁移加密一次
			if (!enc && (pin->i_mode & I_TYPE_MASK) == I_REGULAR) {
				printl("[enc] pid=%d fd=%d ino=%d",fs_msg.source, fd, pin->i_num);
				ensure_file_encrypted(pin);
				enc = 1; // 迁移后视为加密文件 
			}
		}
		for (i = rw_sect_min; i <= rw_sect_max; i += chunk) {
			/* read/write this amount of bytes every time */
			int bytes = min(bytes_left, chunk * SECTOR_SIZE - off);
			rw_sector(DEV_READ,
				  pin->i_dev,
				  i * SECTOR_SIZE,
				  chunk * SECTOR_SIZE,
				  TASK_FS,
				  fsbuf);
			// 对于加密文件，进行解密处理
			if (enc) {
				for (int s = 0; s < chunk; s++) {
					u32 off_in_file = (u32)((i - pin->i_start_sect + s) * SECTOR_SIZE);
					crypt_buf((u8*)fsbuf + s * SECTOR_SIZE, SECTOR_SIZE, pin, off_in_file);
				}
			}	
			if (fs_msg.type == READ) {
				phys_copy((void*)va2la(src, buf + bytes_rw),
					  (void*)va2la(TASK_FS, fsbuf + off),
					  bytes);
			}
			else {	/* WRITE */
				phys_copy((void*)va2la(TASK_FS, fsbuf + off),
					  (void*)va2la(src, buf + bytes_rw),
					  bytes);
				if (enc) {
					for (int s = 0; s < chunk; s++) {
						u32 off_in_file = (u32)((i - pin->i_start_sect + s) * SECTOR_SIZE);
						crypt_buf((u8*)fsbuf + s * SECTOR_SIZE, SECTOR_SIZE, pin, off_in_file);
					}
				}
				rw_sector(DEV_WRITE,
					  pin->i_dev,
					  i * SECTOR_SIZE,
					  chunk * SECTOR_SIZE,
					  TASK_FS,
					  fsbuf);
			}
			off = 0;
			bytes_rw += bytes;
			pcaller->filp[fd]->fd_pos += bytes;
			bytes_left -= bytes;
		}

		if (pcaller->filp[fd]->fd_pos > pin->i_size) {
			/* update inode::size */
			pin->i_size = pcaller->filp[fd]->fd_pos;
			/* write the updated i-node back to disk */
			sync_inode(pin);
		}

		return bytes_rw;
	}
}
