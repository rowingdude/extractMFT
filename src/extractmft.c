#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>

#define MFT_RECORD_SIGNATURE "FILE"
#define MAX_SECTOR_SIZE 4096
#define MFT_RECORD_SIZE 1024

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

typedef struct {
    char     signature[4];                 // "FILE" or "BAAD"
    uint16_t fixup_offset;                 // Update sequence offset
    uint16_t fixup_count;                  // Number of fixup entries
    uint64_t log_sequence_number;          // $LogFile sequence number
    uint16_t sequence_number;              // Sequence number
    uint16_t hard_link_count;              // Hard link count
    uint16_t attribute_offset;             // Offset to first attribute
    uint16_t flags;                        // Flags (0x01 = in use, 0x02 = directory)
    uint32_t used_size;                    // Used size of MFT record
    uint32_t allocated_size;               // Allocated size of MFT record
    uint64_t base_record_reference;        // File reference to base record
    uint16_t next_attribute_id;            // Next attribute ID
    uint16_t padding;                      // Alignment (NTFS 5.0+)
    uint32_t mft_record_number;            // MFT record number (NTFS 5.0+)
} __attribute__((packed)) MFTRecordHeader;

typedef struct {
    uint32_t type_id;                      // Attribute type (e.g., 0x10 = $STANDARD_INFORMATION)
    uint32_t length;                       // Total length of attribute
    uint8_t  non_resident;                 // 0 = resident, 1 = non-resident
    uint8_t  name_length;                  // Length of attribute name (if any)
    uint16_t name_offset;                  // Offset to attribute name
    uint16_t flags;                        // Attribute flags (e.g., compressed, sparse)
    uint16_t attribute_id;                 // Attribute ID
    union {
        struct {                           // Resident attributes
            uint32_t data_length;          // Length of attribute data
            uint16_t data_offset;          // Offset to attribute data
            uint8_t  indexed_flag;         // Indexed flag
            uint8_t  padding;              // Padding
        } resident;
        struct {                           // Non-resident attributes
            uint64_t start_vcn;            // Starting VCN
            uint64_t last_vcn;             // Last VCN
            uint16_t data_run_offset;      // Offset to data runs
            uint16_t compression_unit;     // Compression unit size
            uint32_t padding;              // Padding
            uint64_t allocated_size;       // Allocated size
            uint64_t data_size;            // Actual data size
            uint64_t initialized_size;     // Initialized data size
        } non_resident;
    } data;
} __attribute__((packed)) AttributeHeader;

typedef struct {
    uint64_t creation_time;                // File creation time
    uint64_t modification_time;            // File modification time
    uint64_t mft_modification_time;        // MFT entry modification time
    uint64_t access_time;                  // File access time
    uint32_t file_attributes;              // File attributes (e.g., read-only)
} __attribute__((packed)) StandardInformation;

typedef struct {
    uint64_t parent_directory;             // Parent directory file reference
    uint64_t creation_time;                // File creation time
    uint64_t modification_time;            // File modification time
    uint64_t mft_modification_time;        // MFT entry modification time
    uint64_t access_time;                  // File access time
    uint64_t allocated_size;               // Allocated size
    uint64_t data_size;                    // Actual data size
    uint32_t file_attributes;              // File attributes
    uint16_t ea_reparse;                   // EA or reparse point data
    uint8_t  name_length;                  // Length of file name (in characters)
    uint8_t  name_type;                    // Name type (e.g., POSIX, Win32)

} __attribute__((packed)) FileName;

void ntfs_time_to_string(uint64_t ntfs_time, char *buf, size_t buf_size) {

    uint64_t unix_time = (ntfs_time / 10000000ULL) - 11644473600ULL;
    time_t t = (time_t)unix_time;
    struct tm *tm = gmtime(&t);
    strftime(buf, buf_size, "%Y-%m-%d %H:%M:%S", tm);
}

void log_attribute(FILE *log_file, MFTRecordHeader *header, AttributeHeader *attr, uint8_t *buffer) {
    char time_buf[32];

    if (attr->type_id == 0x10 && !attr->non_resident) { // $STANDARD_INFORMATION
        StandardInformation *si = (StandardInformation *)(buffer + attr->data.resident.data_offset);
        ntfs_time_to_string(si->creation_time, time_buf, sizeof(time_buf));
        fprintf(log_file, "Record %u: Creation Time: %s\n", header->mft_record_number, time_buf);
        ntfs_time_to_string(si->modification_time, time_buf, sizeof(time_buf));
        fprintf(log_file, "Record %u: Modification Time: %s\n", header->mft_record_number, time_buf);
    }
    else if (attr->type_id == 0x30 && !attr->non_resident) { // $FILE_NAME
        FileName *fn = (FileName *)(buffer + attr->data.resident.data_offset);
        wchar_t *name = (wchar_t *)((uint8_t *)fn + sizeof(FileName));
        fprintf(log_file, "Record %u: File Name: ", header->mft_record_number);
        for (int i = 0; i < fn->name_length && i < 255; i++) {
            fputwc(name[i], log_file);
        }
        fputc('\n', log_file);
        fprintf(log_file, "Record %u: File Size: %llu bytes\n", header->mft_record_number, fn->data_size);
        fprintf(log_file, "Record %u: Is Directory: %s\n", header->mft_record_number,
                (header->flags & 0x02) ? "Yes" : "No");
    }
    else if (attr->type_id == 0x80) { // $DATA
        fprintf(log_file, "Record %u: Data Attribute (Non-resident: %s, Size: %llu)\n",
                header->mft_record_number, attr->non_resident ? "Yes" : "No",
                attr->non_resident ? attr->data.non_resident.data_size : attr->data.resident.data_length);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <device_path> <mft_output_file> <log_file>\n", argv[0]);
        fprintf(stderr, "Example: %s /dev/sdb1 mft_output.bin mft_log.txt\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open device: %s\n", strerror(errno));
        return 1;
    }

    int out_fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        fprintf(stderr, "Failed to open MFT output file: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    FILE *log_file = fopen(argv[3], "w");
    if (!log_file) {
        fprintf(stderr, "Failed to open log file: %s\n", strerror(errno));
        close(fd);
        close(out_fd);
        return 1;
    }

    BootSector boot;
    if (read(fd, &boot, sizeof(BootSector)) != sizeof(BootSector)) {
        fprintf(stderr, "Failed to read boot sector: %s\n", strerror(errno));
        fclose(log_file);
        close(fd);
        close(out_fd);
        return 1;
    }

    if (strncmp(boot.oem_id, "NTFS    ", 8) != 0) {
        fprintf(stderr, "Device is not an NTFS partition\n");
        fclose(log_file);
        close(fd);
        close(out_fd);
        return 1;
    }

    if (boot.bytes_per_sector == 0 || boot.bytes_per_sector > MAX_SECTOR_SIZE ||
        boot.sectors_per_cluster == 0 || boot.mft_cluster == 0) {
        fprintf(stderr, "Invalid NTFS parameters\n");
        fclose(log_file);
        close(fd);
        close(out_fd);
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
        fclose(log_file);
        close(fd);
        close(out_fd);
        return 1;
    }

    off_t mft_offset = boot.mft_cluster * boot.sectors_per_cluster * boot.bytes_per_sector;
    if (lseek(fd, mft_offset, SEEK_SET) == (off_t)-1) {
        fprintf(stderr, "Failed to seek to MFT: %s\n", strerror(errno));
        fclose(log_file);
        close(fd);
        close(out_fd);
        return 1;
    }

    uint8_t *buffer = malloc(mft_record_size);
    if (!buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(log_file);
        close(fd);
        close(out_fd);
        return 1;
    }

    ssize_t bytes_read;
    unsigned long long records = 0;

    while ((bytes_read = read(fd, buffer, mft_record_size)) == mft_record_size) {
        MFTRecordHeader *header = (MFTRecordHeader *)buffer;

        if (strncmp(header->signature, MFT_RECORD_SIGNATURE, 4) != 0) {
            if (strncmp(header->signature, "BAAD", 4) == 0) {
                fprintf(log_file, "Record %llu: Corrupted (BAAD signature)\n", records);
            }
            break;
        }

        if (header->fixup_count > 0) {
            uint16_t *fixup_array = (uint16_t *)(buffer + header->fixup_offset);
            uint16_t fixup_value = fixup_array[0];
            for (uint16_t i = 1; i < header->fixup_count; i++) {
                uint16_t *sector_end = (uint16_t *)(buffer + (i * boot.bytes_per_sector) - 2);
                if (*sector_end != fixup_value || fixup_array[i] == 0) {
                    fprintf(log_file, "Record %u: Invalid fixup sequence\n", header->mft_record_number);
                    break;
                }
                *sector_end = fixup_array[i];
            }
        }

        if (header->base_record_reference != 0) {
            fprintf(log_file, "Record %u: Extension record (Base: %llu)\n",
                    header->mft_record_number, header->base_record_reference);
        }

        uint16_t offset = header->attribute_offset;
        while (offset < header->used_size && offset < mft_record_size - sizeof(AttributeHeader)) {
            AttributeHeader *attr = (AttributeHeader *)(buffer + offset);
            if (attr->type_id == 0xFFFFFFFF || attr->length == 0 || offset + attr->length > header->used_size) {
                break;
            }

            if (attr->length < sizeof(AttributeHeader) ||
                (attr->non_resident && offset + attr->data.non_resident.data_run_offset > header->used_size) ||
                (!attr->non_resident && offset + attr->data.resident.data_offset > header->used_size)) {
                fprintf(log_file, "Record %u: Invalid attribute at offset %u\n", header->mft_record_number, offset);
                break;
            }

            log_attribute(log_file, header, attr, buffer + offset);
            offset += attr->length;
        }

        if (write(out_fd, buffer, mft_record_size) != mft_record_size) {
            fprintf(stderr, "Failed to write to MFT output file: %s\n", strerror(errno));
            free(buffer);
            fclose(log_file);
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
    fprintf(log_file, "Total MFT records extracted: %llu\n", records);

    free(buffer);
    fclose(log_file);
    close(fd);
    close(out_fd);
    return 0;
}
