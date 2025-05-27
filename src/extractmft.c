#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#define MFT_RECORD_SIGNATURE "FILE"
#define MAX_SECTOR_SIZE 4096
#define MFT_RECORD_SIZE 1024

// NTFS Boot Sector structure
typedef struct {
    uint8_t  jump_instruction[3];           // Jump to boot code
    char     oem_id[8];                    // "NTFS    "
    uint16_t bytes_per_sector;             // Sector size in bytes
    uint8_t  sectors_per_cluster;          // Sectors per cluster
    uint16_t reserved_sectors;             // Reserved sectors
    uint8_t  fats;                         // Number of FATs (0 for NTFS)
    uint16_t root_entries;                 // Root directory entries (0 for NTFS)
    uint16_t small_sectors;                // Small sector count (0 for NTFS)
    uint8_t  media_descriptor;             // Media descriptor
    uint16_t sectors_per_fat;              // Sectors per FAT (0 for NTFS)
    uint16_t sectors_per_track;            // Sectors per track
    uint16_t heads;                        // Number of heads
    uint32_t hidden_sectors;               // Hidden sectors
    uint32_t large_sectors;                // Large sector count
    uint8_t  physical_drive;               // Physical drive number
    uint8_t  current_head;                 // Current head
    uint8_t  signature;                    // Extended boot signature
    uint8_t  unused;                       // Padding
    uint64_t total_sectors;                // Total sectors in volume
    uint64_t mft_cluster;                  // MFT starting cluster
    uint64_t mft_mirror_cluster;           // MFT mirror starting cluster
    int8_t   clusters_per_mft_record;      // Clusters per MFT record (or negative for bytes)
    uint8_t  reserved1[3];                 // Reserved
    int8_t   clusters_per_index_record;    // Clusters per index record
    uint8_t  reserved2[3];                 // Reserved
    uint64_t volume_serial_number;         // Volume serial number
    uint32_t checksum;                     // Boot sector checksum
} __attribute__((packed)) BootSector;

// Basic MFT Record Header
typedef struct {
    char     signature[4];                 // "FILE"
    uint16_t fixup_offset;                 // Update sequence offset
    uint16_t fixup_count;                  // Number of fixup entries
    uint64_t log_sequence_number;          // $LogFile sequence number
    uint16_t sequence_number;              // Sequence number
    uint16_t hard_link_count;              // Hard link count
    uint16_t attribute_offset;             // Offset to first attribute
    uint16_t flags;                        // Flags (in use, directory)
    uint32_t used_size;                    // Used size of MFT record
    uint32_t allocated_size;               // Allocated size of MFT record
} __attribute__((packed)) MFTRecordHeader;

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <device_path> <output_file>\n", argv[0]);
        fprintf(stderr, "Example: %s /dev/sdb1 mft_output.bin\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open device: %s\n", strerror(errno));
        return 1;
    }

    BootSector boot;
    if (read(fd, &boot, sizeof(BootSector)) != sizeof(BootSector)) {
        fprintf(stderr, "Failed to read boot sector: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    if (strncmp(boot.oem_id, "NTFS    ", 8) != 0) {
        fprintf(stderr, "Device is not an NTFS partition\n");
        close(fd);
        return 1;
    }

    if (boot.bytes_per_sector == 0 || boot.bytes_per_sector > MAX_SECTOR_SIZE ||
        boot.sectors_per_cluster == 0 || boot.mft_cluster == 0) {
        fprintf(stderr, "Invalid NTFS parameters\n");
        close(fd);
        return 1;
    }

    uint32_t mft_record_size;
    if (boot.clusters_per_mft_record >= 0) {
        mft_record_size = boot.clusters_per_mft_record * boot.sectors_per_cluster * boot.bytes_per_sector;
    } else {
        mft_record_size = 1 << (-boot.clusters_per_mft_record);
    }
    if (mft_record_size != MFT_RECORD_SIZE) {
        fprintf(stderr, "Unsupported MFT record size: %u bytes\n", mft_record_size);
        close(fd);
        return 1;
    }

    off_t mft_offset = boot.mft_cluster * boot.sectors_per_cluster * boot.bytes_per_sector;
    if (lseek(fd, mft_offset, SEEK_SET) == (off_t)-1) {
        fprintf(stderr, "Failed to seek to MFT: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    int out_fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        fprintf(stderr, "Failed to open output file: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    uint8_t *buffer = malloc(mft_record_size);
    if (!buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        close(fd);
        close(out_fd);
        return 1;
    }

    ssize_t bytes_read;
    unsigned long long records = 0;

    while ((bytes_read = read(fd, buffer, mft_record_size)) == mft_record_size) {
        MFTRecordHeader *header = (MFTRecordHeader *)buffer;

        if (strncmp(header->signature, MFT_RECORD_SIGNATURE, 4) != 0) {
            break;
        }

        if (header->fixup_count > 0) {
            uint16_t *fixup_array = (uint16_t *)(buffer + header->fixup_offset);
            uint16_t fixup_value = fixup_array[0];
            for (uint16_t i = 1; i < header->fixup_count; i++) {
                uint16_t *sector_end = (uint16_t *)(buffer + (i * boot.bytes_per_sector) - 2);
                if (*sector_end != fixup_value || fixup_array[i] == 0) {
                    fprintf(stderr, "Invalid fixup sequence in record %llu\n", records);
                    break;
                }
                *sector_end = fixup_array[i];
            }
        }

        if (write(out_fd, buffer, mft_record_size) != mft_record_size) {
            fprintf(stderr, "Failed to write to output file: %s\n", strerror(errno));
            free(buffer);
            close(fd);
            close(out_fd);
            return 1;
        }
        records++;
    }

    if (bytes_read < 0) {
        fprintf(stderr, "Error reading MFT: %s\n", strerror(errno));
    }

    printf("Extracted %llu MFT records\n", records);

    free(buffer);
    close(fd);
    close(out_fd);
    return 0;
}
